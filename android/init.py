import re
from typing import Dict, List
from android.dac import AID_MAP_INV, Cred
from android.property import PROPERTY_KEY, PROPERTY_VALUE, AndroidPropertyList
from android.sepolicy import SELinuxContext
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from fs.filesystempolicy import FileSystemPolicy
from utils.logger import Logger

# 创建类型别名
Section = List[List[str]]
Option = List[str]

class TriggerCondition():
    '''
            on <trigger> [&& <trigger>]*
        <command>...
    '''
    def __init__(self, props: AndroidPropertyList, condition: List[str]):
        self.props: AndroidPropertyList = props
        self.raw_condition: List[str] = condition       # 保存原始的触发条件
        self.stage_trigger: str | None = None           # 两个变量都是表示触发的条件,stage_trigger只出现一次
        self.property_conditions: Dict[str, str] = {}
        self._parse_trigger()

    def new_stage(self, stage: str):
        '''if the trigger <stage> triggers this event'''
        # print(self.stage_trigger, stage)
        # exit(1)
        if self.stage_trigger == stage or (self.stage_trigger is None and stage == "boot"):
            val = True

            for p, v in self.property_conditions.items():
                val = True if p in self.props and \
                    (self.props[p] == v or v == "*") else False

                if not val:
                    break

            return val
        else:
            return False

    def setprop(self, new_prop):
        if new_prop not in self.property_conditions:
            return False

        val = True

        for p, v in self.property_conditions.items():
            val = True if p in prop and (prop[p] == v or v == "*") else False

            if not val:
                break

        return val

    def _parse_trigger(self):
        expect_and = False  # flag to indicate if we expect an &&
        for cond in self.raw_condition:
            if cond == "&&" and not expect_and:
                Logger.warning("Trigger condition: unexpected &&")
                return
            elif cond != "&&" and expect_and:
                Logger.warning("Trigger condition: expected &&")
                return

            expect_and = False

            if cond.startswith("property:"):
                cond = cond[len("property:"):]  # 去掉property:前缀
                match = re.match(r'(%s)=(%s)' % (PROPERTY_KEY.pattern, PROPERTY_VALUE.pattern), cond)

                if not match:
                    Logger.warning("Trigger condition %s is invalid", cond)
                else:
                    prop, value = match.groups()
                    self.property_conditions[prop] = value

                expect_and = True
            elif cond == "&&":
                pass
            else:
                self.stage_trigger = cond   # only once I promise it 
                expect_and = True

    def __repr__(self):
        triggers = []

        if self.stage_trigger:
            triggers += [str(self.stage_trigger)]

        for k, v in self.property_conditions.items():
            triggers += ["%s=%s" % (k, v)]

        return "<TriggerCondition %s>" % (" && ".join(triggers))

class AndroidInitAction():
    '''on <cond> <cmds> ? TODO explain it'''
    def __init__(self, condition: TriggerCondition):
        self.condition: TriggerCondition = condition
        self.commands: List[List[str]] = []

    def add_command(self, cmd: str, args: List[str]):
        self.commands += [[cmd] + args]

    def __repr__(self):
        return "<AndroidInitAction %d commands on %s>" % (len(self.commands), repr(self.condition))


class AndroidInitService():
    def __init__(self, name: str, args: List[str]):
        self.service_class: str = "default"
        self.service_groups: List[str] = []
        self.name = name
        self.args = args
        self.options: List[Option] = []

        self.cred: Cred = Cred()
        # default uid/gid is root!
        self.cred.uid = 0
        self.cred.gid = 0

        
        self.disabled = False
        self.oneshot = False
    
    def add_option(self, option: str, args: List[str]):
        if option == "user":
            self.cred.uid = AID_MAP_INV.get(args[0], 9999)
            if self.cred.uid == 9999:
                Logger.warning("Missing AID definition for user: %s", args[0])
        elif option == "capabilities":
            for cap in args:
                self.cred.cap.add('ambient', cap)
        elif option == "group":
            self.cred.gid = AID_MAP_INV.get(args[0], 9999)
            if self.cred.gid == 9999:
                Logger.warning("Missing AID definition for group: %s", args[0])

            for group in args[1:]:
                try:
                    self.cred.add_group(group)
                except KeyError:
                    Logger.warning("Unabled to find AID mapping for group %s", group)
        elif option == "disabled":
            self.disabled = True
        elif option == "class":
            self.service_class = args[0]    # str

            if len(args) > 1:
                self.service_groups = args[1:]
        elif option == "oneshot":
            self.oneshot = True
        elif option == "seclabel":
            self.cred.sid = SELinuxContext.FromString(args[0])
        else:
            self.options += [[option] + args]


class AndroidInit():
    def __init__(self, asp: AndroidSecurityPolicy):
        self.asp = asp
        self.services: Dict[str, AndroidInitService] = {} # [str] -> AndroidInitService
        self.actions: List[AndroidInitAction] = []
    
    def determine_hardware(self) -> str:
        rohw = 'ro.hardware'
        if rohw not in self.asp.properties:
            import re
            for pattern, regex in [
                ("*uevent*rc", r'.*ueventd\.([-_a-zA-Z0-9]+)\.rc'),
                ("*fstab.*",   r'.*fstab\.([-_a-zA-Z0-9]+)'),]:

                results = self.asp.fs_policies['system'].find(pattern)
                for result in results:
                    match = re.match(regex, result)

                    if match:
                        ro_hardware_guess = match.group(1)
                        self.asp.properties[rohw] = ro_hardware_guess
                        print("[!] " + ro_hardware_guess)
                        break
        if ro_hardware_guess:
            Logger.info(f"Guessing ro.hardware as {ro_hardware_guess}")
            self.asp.properties[rohw] = ro_hardware_guess
        return self.asp.properties[rohw]
    
    def read_configs(self, init_rc_base: str):
        first_init = self.read_init_rc(init_rc_base)

    def read_init_rc(self, path: str):
        '''Reads the init.rc file and returns a list of sections'''
        if path not in self.asp.combined_fs.files:
            raise FileNotFoundError(f"init.rc file not found at {path}")
        rc_path = self.asp.combined_fs.files[path].original_path

        with open(rc_path, 'r') as fp:
            rc_lines = fp.read()

        pending_imports: List[str] = []     # [str]
        sections: List[Section] = []        # [sections]
        current_section: Section = None     # ? type [['no','init'],['cmd','parms']] : [[str]]
        line_continue: bool = False
        
        # 读取所有的init配置的文件，将其分割成section
        for line in rc_lines.split("\n"):
            if re.match('^(\s*#)|(\s*$)', line): continue   # ignore comments and empty lines
            line = re.sub('\s+', " ", line)                # remove extra spaces
            components: List[str] = list(filter(lambda x: len(x) > 0, line.split(" "))) # split by spaces
            action = components[0]
            if action in ['import', 'on', 'service']:   # 开始一个新的section
                if current_section is not None and len(current_section):
                    sections += [current_section]

                current_section = []
            elif current_section is None:
                # ignore actions/commands before the first section
                continue

            line_continue_next: bool = components[-1] == "\\"

            # erase trailing slash
            if line_continue_next:
                components = components[:-1]

            if line_continue:
                current_section[-1] += components
            else:
                current_section += [components]

            line_continue = line_continue_next

        # Get trailing section
        if current_section is not None and len(current_section):
            sections += [current_section]

        # 处理每一个section
        for section in sections:
            action = section[0][0]  # str
            args = section[0][1:]   # [str]
            body = section[1:]      # [[str]]

            if action == "import":
                pending_imports += [args[0]]
            elif action == "service":
                service_name = args[0]  # str
                service_args = args[1:] # [str]
                self._add_service(service_name, service_args, body)
            elif action == "on":
                # not handled for now
                condition = args
                commands = body

                self._add_action(condition, commands)
            else:
                raise ValueError("Unknown section type %s" % (action))
        
        for imp in pending_imports:
            # self._import(imp)
            pass

    def _add_service(self, name: str, args: List[str], body: Section):
        # TODO: handle override
        if name in self.services: return
        service: AndroidInitService = AndroidInitService(name, args)

        for opt in body:
            opt_name = opt[0]   # str
            opt_args = opt[1:]  # [str]
            service.add_option(opt_name, opt_args)

        self.services[name] = service   # add to AndroidInit.services dict

    def _add_action(self, condition: List[str], commands: List[List[str]]):
        '''on <trigger condition> <cmds>'''
        trigger_cond = TriggerCondition(self.props, condition)
        action = AndroidInitAction(trigger_cond)
        for cmd in commands:
            action.add_command(cmd[0], cmd[1:])
        self.actions += [action]