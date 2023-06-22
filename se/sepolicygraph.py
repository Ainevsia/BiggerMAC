from typing import Dict, List, Set, Union
import setools
from setools.policyrep import TERule, AVRuleXperm, AVRule, FileNameTERule, TERuletype, Genfscon, FSUse, Type
import networkx as nx
from utils.logger import Logger

class Class2:
    def __init__(self, inherits: Union[str, None], perms: List[str]):
        self.inherits: Union[str, None] = inherits
        self.perms: List[str] = perms

class PolicyGraph:
    def __init__(self):
        self.classes: Dict[str, Class2] = {}

        self.attributes: Dict[str, List[str]] = {}
        '''所有拥有 attribute 的 type 组成的list'''

        self.commons: Dict[str, List[str]] = {}
        '''记录一个common的所有perms'''

        self.types: Dict[str, List[str]] = {}
        '''一个type的所有attribute，如果有的话；如果是alias，记录它的type'''

        self.aliases: Dict[str, bool] = {}
        '''记录一个type是否实际上是一个alias'''

        self.genfs: Dict[str, List[Genfscon]] = {}
        '''记录fs文件系统路径下的label'''

        self.fs_use: Dict[str, FSUse] = {}
        '''由于伪文件系统不支持labeling，使用fs_use_task记录标签'''

        self.G_allow: nx.MultiDiGraph = nx.MultiDiGraph()
        self.G_transition: nx.MultiDiGraph = nx.MultiDiGraph()

class SELinuxPolicyGraph(setools.SELinuxPolicy):
    def build_graph(self) -> PolicyGraph:
        pg = PolicyGraph()

        for attr in self.typeattributes():
            pg.attributes[str(attr)] = []   # touch

        for com in self.commons():
            pg.commons[str(com)] = list(com.perms)
        
        for cls in self.classes():
            try:
                parent = str(cls.common)    # only once i promise, if exists, may except NoCommon
                pg.commons[parent]          # just ensure it exists
            except:
                parent = None
            perms: List[str] = list(cls.perms)
            pg.classes[str(cls)] = Class2(parent, perms)

        for typ in self.types():
            name = str(typ)

            for attr in typ.attributes():
                pg.attributes[str(attr)] += [str(typ)]

            for alias in typ.aliases():
                types[str(alias)] = name
                aliases[str(alias)] = True

            pg.types[name] = [str(x) for x in typ.attributes()]

        # define fs_use contexts
        for fs_use_ in self.fs_uses():
            # The fs_use_task statement is used to allocate a security context to pseudo filesystems that support task related services such as pipes and sockets.
            # The statement definition is:
            # fs_use_task fs_name fs_context;
            # fs_use_task pipefs u:object_r:pipefs:s0;
            fs_use[str(fs_use_.fs)] = fs_use_

        # https://selinuxproject.org/page/FileStatements

        # define genfs contexts
        for genfscon_ in self.genfscons():
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

        for terule_ in self.terules():
            
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

        return pg
    

