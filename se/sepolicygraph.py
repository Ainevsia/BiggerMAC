from typing import Dict, List, Set, Union
import setools
from setools.policyrep import TERule, AVRuleXperm, AVRule, FileNameTERule

from utils.logger import Logger

class SELinuxPolicyGraph(setools.SELinuxPolicy):
    pass
    # 不知道为什么，这里不能写构造函数，否则会报错
    #     super().__init__(policy_file)
    # TypeError: object.__init__() takes exactly one argument (the instance to initialize

    def find_useless_type(self):
        """Find useless types and attributes"""
        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        # base identifiers
        classes: Dict[str, Dict[str, Union[List[str], str]]] = {}
        attributes: Dict[str, List[str]] = {}   # 所有拥有attribute的type
        commons: Dict[str, List[str]] = {}      # 记录一个common的所有perms
        types: Dict[str, List[str]] = {}        # 一个type的所有attribute，如果有的话；如果是alias，记录它的type
        aliases: Dict[str, bool] = {}
        ta_used: Set[str] = set()               # 记录已经使用过的types和attributes

        # define type attributes
        Logger.debug(f'typeattributes len: {len(self.typeattributes())}')
        for attribute_ in cond_sort(self.typeattributes()):
            attributes[str(attribute_)] = []    # empty list
        print(len(attributes))
        print([i for i in attributes][:10])
        # access vectors
        Logger.debug(f'commons len: {len(self.commons())}')
        for common_ in cond_sort(self.commons()):
            commons[str(common_)] = [str(x) for x in common_.perms]
        print(len(commons))
        print(commons)
        # security object classes
        Logger.debug(f'classes len: {len(self.classes())}')
        for class_ in cond_sort(self.classes()):
            try:
                parent: str = str(class_.common)
                commons[parent] # just ensure it exists
            except:
                parent = None

            perms: List[str] = [str(x) for x in class_.perms]
            # class class_id [ inherits common_set ] [ { perm_set } ]
            classes[str(class_)] = { "perms" : perms, "parent" : parent }
            # print(classes[str(class_)])
        print(len(classes))
        print([i for i in classes][:20])


        # define types, aliases and attributes
        #                                        type type_id [alias alias_id] [, attribute_id];
        Logger.debug(f'types len: {len(self.types())}')
        for type_ in cond_sort(self.types()):
            name: str = str(type_)  # typename type_id
            for attr in type_.attributes():
                attributes[str(attr)] += [name]
            for alias in type_.aliases():
                types[str(alias)] = name
                aliases[str(alias)] = True

            types[name] = [str(x) for x in type_.attributes()]
        print(len(types))
        
        # define type enforcement rules
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            # allow/dontaudit/auditallow/neverallow rules
            if isinstance(terule_, AVRuleXperm) or isinstance(terule_, AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))

            # type_* type enforcement rules
            elif isinstance(terule_, TERule):
                # type_transition ITouchservice crash_dump_exec:process crash_dump;
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                ta_used.add(str(terule_.source))    # ITouchservice
                ta_used.add(str(terule_.target))    # crash_dump_exec
                ta_used.add(str(terule_.default))   # crash_dump
            elif isinstance(terule_, FileNameTERule):
                # type_transition zygote system_data_file:dir ctrl_socket_file ctrl_socket;
                # type_transition system_server system_data_file:sock_file system_ndebug_socket ndebugsocket;
                # type_transition system_server system_data_file:dir push_data_file hwpush_files;
                # type_transition system_server system_data_file:dir data_system_iaware iaware;
                # type_transition system_server system_data_file:dir app_acc_file app_acc;
                # type_transition hal_wifi_supplicant_default wifi_data_file: dir   wpa_socket   sockets;
                # type_transition source_type                 target_type   : class default_type object_name;
                
                ta_used.add(str(terule_.source))
                ta_used.add(str(terule_.target))
                ta_used.add(str(terule_.default))
                ta_used.add(str(terule_.filename))  # filename type_transition rule

            else:
                # this is unreachable: AnyTERule = Union["AVRule", "AVRuleXperm", "TERule", "FileNameTERule"]
                raise RuntimeError("Unhandled TE rule")
        
        print("--= Useless attributes list =--")
        for k in attributes.keys():
            if k not in ta_used:
                print(k)

        print("--= Useless types list =--")
        for k in types.keys():
            if k not in ta_used:
                is_used_in_attr = False
                for a in types[k]:
                    if a in ta_used:
                        is_used_in_attr = True
                        break
                if is_used_in_attr == False:
                    print(k)

        print("--= done =--")
        return

    def build_graph(self):
        pass