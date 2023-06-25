import os
import re
import stat
from typing import Dict, List
from android.dac import AID_MAP_INV, Cred
from android.property import PROPERTY_KEY, PROPERTY_VALUE, AndroidPropertyList
from android.sepolicy import SELinuxContext
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from fs.filesystempolicy import FilePolicy, FileSystemPolicy
from utils.logger import Logger

# 创建类型别名
Section = List[List[str]]
Option = List[str]
Command = List[str]

class TriggerCondition:
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

    def new_stage(self, stage: str) -> bool:
        '''determine if the trigger <stage> should trigger this event'''
        if self.stage_trigger == stage or (self.stage_trigger is None and stage == "boot"):
            for p, v in self.property_conditions.items():   # 遍历所有的属性条件
                cont = True if p in self.props and (self.props[p] == v or v == "*") else False
                if not cont: return False
            return True
        else:
            return False

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

class AndroidInitAction:
    '''on <cond> <cmds> ? TODO explain it'''
    def __init__(self, condition: TriggerCondition):
        self.condition: TriggerCondition = condition
        self.commands: List[Command] = []

    def add_command(self, cmd: str, args: List[str]):
        self.commands += [[cmd] + args]

    def __repr__(self):
        return "<AndroidInitAction %d commands on %s>" % (len(self.commands), repr(self.condition))

class AndroidInitService:
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

        
        self.disabled: bool = False
        self.oneshot: bool = False
    
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
                    Logger.warning(f"Missing AID definition for group: {group}")
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

class AndroidInit:
    def __init__(self, asp: AndroidSecurityPolicy):
        self.asp = asp
        self.services: Dict[str, AndroidInitService] = {} # [str] -> AndroidInitService
        self.actions: List[AndroidInitAction] = []

         # Runtime events
        self.queue: List[AndroidInitAction] = [] 
    
    def determine_hardware(self) -> str:
        rohw = 'ro.hardware'
        if rohw not in self.asp.properties:
            import re
            for pattern, regex in [
                ("*fstab.*",   r'.*fstab\.([-_a-zA-Z0-9]+)'),
                # ("*uevent*rc", r'.*ueventd\.([-_a-zA-Z0-9]+)\.rc'),
            ]:

                results = self.asp.fs_policies['vendor'].find(pattern)
                for result in results:
                    match = re.match(regex, result)

                    if match:
                        ro_hardware_guess = match.group(1)
                        self.asp.properties[rohw] = ro_hardware_guess
                        Logger.info(f"Guessing ro.hardware as {ro_hardware_guess}")
                        break
        if ro_hardware_guess:
            Logger.info(f"Guessing ro.hardware as {ro_hardware_guess}")
            self.asp.properties[rohw] = ro_hardware_guess
        return self.asp.properties[rohw]
    
    def read_configs(self, init_rc_base: str = "/init.rc"):
        first_init = self.read_init_rc(init_rc_base)

        init_files = self._list_mount_init_files("system")
        init_files += self._list_mount_init_files("vendor")
        init_files += self._list_mount_init_files("odm")

        for init_file in init_files:
            self.read_init_rc(init_file)

    def read_init_rc(self, path: str):
        '''Reads the init.rc file and returns a list of sections'''
        if path not in self.asp.combined_fs:
            Logger.error(f"init.rc file not found at {path}")
            return
            # raise FileNotFoundError(f"init.rc file not found at {path}")
        rc_path = self.asp.combined_fs[path]

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
            self._import(imp)

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
        trigger_cond = TriggerCondition(self.asp.properties, condition)
        action = AndroidInitAction(trigger_cond)
        for cmd in commands:
            action.add_command(cmd[0], cmd[1:])
        self.actions += [action]
    
    def _list_mount_init_files(self, mount_point: str) -> List[str]:
        '''List all init files in a mount point'''
        fsp: FileSystemPolicy = self.asp.fs_policies[mount_point]
        # If a segment is an absolute path, then all previous segments are ignored and 
        # joining continues from the absolute path segment.
        # get rid of the first / in the path
        return [os.path.join('/', mount_point, f[1:]) for f in fsp.find("/etc/init/*.rc")]
        
    def boot_system(self):
        # this is used to bypass dm-verity/FDE on AOSP ? TODO: verify
        self.asp.properties["vold.decrypt"] = "trigger_post_fs_data"
        self.new_stage_trigger('early-init')
        self.main_loop()

        # TODO: android version check for this
        self.asp.combined_fs.add_mount_point("/proc", "proc", "proc", ["rw,relatime,gid=3009,hidepid=2".split(",")])
        self.asp.combined_fs.add_mount_point("/sys", "sysfs", "sysfs", ["rw","seclabel","relatime"])

        uevent_files = [
            "/ueventd.rc", "/vendor/ueventd.rc", "/odm/ueventd.rc",
            "/ueventd." + self.asp.properties.get_default("ro.hardware") + ".rc"]

        for f in uevent_files:
            try:
                self.read_uevent_rc(f)
            except IOError:
                pass

        self.new_stage_trigger('init')
        self.new_stage_trigger('late-init')

        # other stages will be handled by internal actions
        self.main_loop()

    def read_uevent_rc(self, path: str):
        if path not in self.asp.combined_fs: return
        rc_path: str = self._init_rel_path(path)
        rc_lines = ""

        with open(rc_path, 'r') as fp:
            rc_lines = fp.read()

        for line in rc_lines.split("\n"):
            if re.match('^(\s*#)|(\s*$)', line): continue
            line = re.sub('\s+', " ", line)
            components = list(filter(lambda x: len(x) > 0, line.split(" ")))
            
            fn = components[0]

            fn_expand = ""
            if fn.startswith("/dev") and len(components) == 4:
                mode = int(components[1], 8) | stat.S_IFCHR
                user = components[2]
                group = components[3]

                user = AID_MAP_INV.get(user, 9999)
                group = AID_MAP_INV.get(group, 9999)

                fn_expand = fn
            elif fn.startswith("/sys") and len(components) == 5:
                node_name = components[1]
                mode = int(components[2], 8) | stat.S_IFREG
                user = components[3]
                group = components[4]

                user = AID_MAP_INV.get(user, 9999)
                group = AID_MAP_INV.get(group, 9999)

                fn_expand = fn + "/" + node_name
            else:
                continue

            file_policy = FilePolicy.create_pseudo_file(mode, user, group)
            self._add_uevent_file(fn_expand, file_policy)

    def new_stage_trigger(self, stage: str):
        for action in self.actions:
            if action.condition.new_stage(stage):   # if trigger
                self.queue_action(action)           # queue action

    def queue_action(self, action: AndroidInitAction):
        '''Queue an action to be executed'''
        if action in self.queue: return # do not double queue actions
        self.queue.append(action)

    def main_loop(self):
        '''Main loop of the init process (executes queued actions) '''
        while len(self.queue):
            action = self.queue.pop(0)
            for cmd in action.commands:
                self.execute(cmd[0], cmd[1:])
    
    def _add_uevent_file(self, path: str, file_policy: FilePolicy):
        if not path.startswith("/dev") and not path.startswith("/sys"): return
        if '*' in path: path = path.replace('*', '0')
        path = os.path.normpath(path)
        self._expand_kernelfs_dirs(path)
        self.asp.combined_fs.add_or_update_file(path, file_policy)  # TODO ? deepcopy ?
        pass

    def _expand_kernelfs_dirs(self, path: str):
        """
        Use the default permissions for creating /sys/* or /dev/* directories
        """
        total_path = "/"

        # Ignore the last, path as we're creating that next
        for component in os.path.normpath(path).split(os.sep)[1:-1]:
            # 递归创建目录 /sys/* or /dev/* 
            total_path = os.path.join(total_path, component)

            ## Sysfs default permissions
            # directories - 755
            # files - 444 (644 for writeable ones)
            #
            ## Devfs default permissions
            # directories - 755
            # files - 400 (600 for writeable ones)

            if total_path not in self.asp.combined_fs:
                fp = FilePolicy.create_pseudo_file(AID_MAP_INV['root'], AID_MAP_INV['root'], 0o755 | stat.S_IFDIR)
                self.asp.combined_fs.add_file(total_path, fp)   # just directory

    def lazy_init_uevent(self, path: str, mode: int):
        if path not in self.asp.combined_fs:
            if path.startswith("/dev"):     mode = mode | stat.S_IFCHR
            elif path.startswith("/sys"):   mode = mode | stat.S_IFREG
            self._add_uevent_file(path, FilePolicy.create_pseudo_file(AID_MAP_INV['root'], AID_MAP_INV['root'], mode))

    def expand_properties(self, string: str) -> str:
        new_string: str = string

        for m in re.finditer(r'\$\{' + PROPERTY_KEY.pattern + r'\}', string):
            key = m.group(0)[2:-1]

            # silently fail a property lookup
            if key in self.asp.properties:
                value = self.asp.properties[key]
            else:
                value = ""

            new_string = new_string.replace(m.group(0), value)

        return new_string

    def _init_rel_path(self, path: str) -> str:
        return self.asp.combined_fs[path]

    def execute(self, cmd: str, args: List[str]):
        '''Execute a command'''
        # Logger.debug("Executing command: %s %s", cmd, args)
        if cmd == "trigger":
            assert len(args) == 1
            self.new_stage_trigger(args[0]) # trigger a new stage
        elif cmd == "mkdir":
            '''mkdir <path> [mode] [owner] [group]'''
            path = args[0]
            user = 0
            group = 0
            perm = 0o755    # default permission is 755 (rwxr-xr-x)

            if len(args) > 1:
                try:
                    perm = int(args[1], 8)
                except ValueError:
                    Logger.warning("Malformed mkdir: %s", args)
                    return
            if len(args) > 2:
                user: int = AID_MAP_INV.get(args[2], 9999)
            if len(args) > 3:
                group: int = AID_MAP_INV.get(args[3], 9999)
            if user == 9999:
                Logger.warning("Missing AID definition for user: %s", args[2])
            if group == 9999:
                Logger.warning("Missing AID definition for group: %s", args[3])

            self.asp.combined_fs.mkdir(os.path.normpath(path), user, group, perm)
        elif cmd == "chown":
            if len(args) < 3: return
            user = AID_MAP_INV.get(args[0], 9999)
            group = AID_MAP_INV.get(args[1], 9999)

            path = args[2]

            # Try to instantiate it anyways (if it's not in the combined_fs)
            if path not in self.asp.combined_fs:
                if path.startswith("/dev"):
                    mode = 0o0600 | stat.S_IFCHR
                elif path.startswith("/sys"):
                    mode = 0o0644 | stat.S_IFREG
                else:
                    return

                fp: FilePolicy = FilePolicy.create_pseudo_file(user, group, mode)
                

                self._add_uevent_file(path, fp)

            self.asp.combined_fs.chown(path, user, group)
        elif cmd == "chmod":
            '''chmod <mode> <path>'''
            mode: int = int(args[0], 8)
            path: str = args[1]

            # Try to instantiate it anyways
            self.lazy_init_uevent(path, mode)
            self.asp.combined_fs.chmod(path, mode)
        elif cmd == "copy":
            '''copy <src> <dst> [mode] [owner] [group]'''
            pass
        elif cmd == "rm":
            pass
        elif cmd == "rmdir":
            pass
        elif cmd == "setprop":
            pass
        elif cmd == "enable":
            # enable <service>
            service: str = args[0]
            if service in self.services:
                if self.services[service].disabled:
                    self.services[service].disabled = False
        elif cmd == "write":
            pass
        elif cmd == "mount":
            # mount <fstype> <device> <path> [options]
            fstype = args[0]
            device = args[1]
            path = args[2]
            options: List[List[str]] = []
            if len(args) > 3:
                for o in args[3:]:
                    options += o.split(",")

            if path in self.asp.combined_fs.mount_points: return

            self.asp.combined_fs.add_mount_point(path, fstype, device, options)
        elif cmd == "mount_all":
            path = args[0]
            late_mount = "--late" in args

            try:
                with open(self._init_rel_path(self.expand_properties(path)), 'r') as fp:
                    fstab_data: str = fp.read()
                    entries = self.parse_fstab(fstab_data)
            except IOError:
                Logger.warning("Failed to open fstab file: %s", path)
                return

            for entry in entries:
                if late_mount and "latemount" not in entry["fsmgroptions"]: continue
                if not late_mount and "latemount" in entry["fsmgroptions"]: continue
                if entry["path"] in self.asp.combined_fs.mount_points: continue

                self.asp.combined_fs.add_mount_point(entry["path"], entry["fstype"], entry["device"], entry["options"])

    def parse_fstab(self, data: str) -> List[Dict[str, str]]:
        entries: List[Dict[str, str]] = []

        for line in data.split("\n"):
            if re.match('^(\s*#)|(\s*$)', line): continue
            line = re.sub('\s+', " ", line)
            components = list(filter(lambda x: len(x) > 0, line.split(" ")))
            
            device = components[0]
            mount_path = components[1]
            fstype = components[2]
            options = components[3].split(",")

            if len(components) > 4:
                fsmgroptions = components[4].split(",")
            else:
                fsmgroptions = []

            entries += [{"device":device, "path" : mount_path, "fstype" : fstype, "options" : options,
                "fsmgroptions" : fsmgroptions}]

        return entries

    def _import(self, path: str):
        self.read_init_rc(self.expand_properties(path))

