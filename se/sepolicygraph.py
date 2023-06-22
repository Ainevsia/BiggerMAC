from typing import Dict, List, Set, Union
import setools
from setools.policyrep import TERule, AVRuleXperm, AVRule, FileNameTERule, TERuletype, Genfscon, FSUse, Type
import networkx as nx
from utils.logger import Logger

class PolicyGraph():
    ''''''
    def __init__(self, 
                 classes: Dict[str, Dict[str, Union[List[str], str]]], 
                 attributes: Dict[str, List[str]], 
                 types: Dict[str, List[str]], 
                 aliases: Dict[str, bool], 
                 genfs: Dict[str, List[Genfscon]], 
                 fs_use: Dict[str, FSUse] , 
                 G_allow: nx.MultiDiGraph, 
                 G_transition: nx.MultiDiGraph):
        # PolicyGraph(classes, attributes, types, aliases, genfs, fs_use, G_allow, G_transition)
        self.classes = classes
        self.attributes = attributes
        '''所有拥有 attribute 的 type 组成的list'''
        self.types = types
        '''一个type的所有attribute，如果有的话；如果是alias，记录它的type'''
        self.aliases = aliases
        self.genfs = genfs
        self.fs_use = fs_use
        self.G_allow: nx.MultiDiGraph = G_allow
        self.G_transition: nx.MultiDiGraph = G_transition

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

    def build_graph(self) -> PolicyGraph:
        """Create a graph for querying."""
        G_allow = nx.MultiDiGraph()
        G_transition = nx.MultiDiGraph()

        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)


        classes: Dict[str, Dict[str, Union[List[str], str, None]]] = {}
        attributes: Dict[str, List[str]] = {}   # 所有拥有attribute的type
        commons: Dict[str, List[str]] = {}      # 记录一个common的所有perms
        types: Dict[str, List[str]] = {}        # 一个type的所有attribute，如果有的话；如果是alias，记录它的type
        aliases: Dict[str, bool] = {}           # 记录一个type是否实际上是一个alias
        fs_use: Dict[str, FSUse] = {}           # 由于伪文件系统不支持labeling，使用fs_use_task记录标签
        genfs: Dict[str, List[Genfscon]] = {}   # 记录fs文件系统路径下的label

        # define type attributes
        for attribute_ in cond_sort(self.typeattributes()):
            attributes[str(attribute_)] = []

        # access vectors
        for common_ in cond_sort(self.commons()):
            commons[str(common_)] = [str(x) for x in common_.perms]

        # security object classes
        for class_ in cond_sort(self.classes()):
            try:
                parent = str(class_.common)
                commons[parent] # just ensure it exists
            except:
                parent = None

            perms = [str(x) for x in class_.perms]
            classes[str(class_)] = { "perms" : perms, "parent" : parent }

        # define types, aliases and attributes
        for type_ in cond_sort(self.types()):
            name = str(type_)

            for attr in type_.attributes():
                attributes[str(attr)] += [str(type_)]

            for alias in type_.aliases():
                types[str(alias)] = name
                aliases[str(alias)] = True

            types[name] = [str(x) for x in type_.attributes()]

        # define fs_use contexts
        for fs_use_ in cond_sort(self.fs_uses()):
            # The fs_use_task statement is used to allocate a security context to pseudo filesystems that support task related services such as pipes and sockets.
            # The statement definition is:
            # fs_use_task fs_name fs_context;
            # fs_use_task pipefs u:object_r:pipefs:s0;
            fs_use[str(fs_use_.fs)] = fs_use_

        # https://selinuxproject.org/page/FileStatements

        # define genfs contexts
        for genfscon_ in cond_sort(self.genfscons()):
            # The genfscon statement is used to allocate a security context to filesystems that 
            # cannot support any of the other file labeling statements 
            # (fs_use_xattr, fs_use_task or fs_use_trans)

            # genfscon fs_name        partial_path fs_context
            # genfscon binfmt_misc    /            u:object_r:binfmt_miscfs:s0"
            fs = genfscon_.fs
            if fs not in genfs: genfs[fs] = []
            genfs[fs] += [genfscon_]
            '''
            genfscon proc / system_u:object_r:proc_t:s0
            genfscon proc /sysvipc system_u:object_r:proc_t:s0
            genfscon proc /fs/openafs system_u:object_r:proc_afs_t:s0
            genfscon proc /kmsg system_u:object_r:proc_kmsg_t:s15:c0.c255
            '''




        cnt = 0
        edges_to_add = 0

        for terule_ in cond_sort(self.terules()):
            
            # Logger.debug("Processing : " + str(terule_))
            # from IPython import embed; embed()
            # exit(233)
            if isinstance(terule_, AVRuleXperm):
                perms = terule_.perms
            elif isinstance(terule_, AVRule):
                perms = terule_.perms
                assert(type(perms) == frozenset)
                
                if terule_.ruletype == TERuletype.allow or terule_.ruletype == TERuletype.auditallow:
                    u_type = str(terule_.source)
                    v_type = str(terule_.target)

                    # make sure we're not dealing with aliases: only types and attributes
                    assert u_type not in aliases
                    assert v_type not in aliases

                    # Add an individual edge from u -> v for each perm
                    #for x in perms:
                    G_allow.add_edge(u_type, v_type, teclass=str(terule_.tclass), perms=[str(x) for x in perms])

                    # G = G_allow
                    # nx.set_node_attributes(G, 'filled,solid', 'style')
                    # import pygraphviz
                    # AG = nx.nx_agraph.to_agraph(G)
                    # AG.layout(prog='sfdp')
                    # AG.draw("G_allow.svg", prog="sfdp", format='svg', args='-Gsmoothing=rng -Goverlap=prism2000 -Goutputorder=edgesfirst -Gsep=+2')
                    # cnt += 1
                    # if cnt > 10:
                    #     exit(2)
            elif isinstance(terule_, TERule) or isinstance(terule_, FileNameTERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                assert terule_.ruletype == TERuletype.type_transition
                # from IPython import embed; embed(); exit(1)
                # type_transition ITouchservice crash_dump_exec:process crash_dump;
                u_type = str(terule_.source)
                # technically target is not the target
                # default is the target type, whereas target is the object used to start the transition
                v_type = str(terule_.default)

                assert u_type not in aliases
                assert v_type not in aliases

                file_qualifier = None

                try:
                    file_qualifier = str(terule_.filename)
                except:
                    pass

                G_transition.add_edge(u_type, v_type,
                                      teclass=str(terule_.tclass),
                                      through=str(terule_.target),
                                      name=file_qualifier)
            else:
                raise RuntimeError("Unhandled TE rule")


            try:
                terule_.conditional
                raise ValueError("Policy has conditional rules. Not supported for SEAndroid graphing")
            except:
                pass


        
        Logger.debug("Finished processing TE rules")

        return PolicyGraph(classes, attributes, types, aliases, genfs, fs_use, G_allow, G_transition)
    

