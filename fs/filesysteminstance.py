import copy
from fnmatch import fnmatch
import os
import re
import networkx as nx
from typing import Dict, List, Set, Tuple, Union
from android.dac import Cred
from android.init import AndroidInit, AndroidInitService
from android.sepolicy import SELinuxContext
from fs.filecontext import AndroidFileContext
from fs.filesystempolicy import FilePolicy
from se.graphnode import FileNode, GraphNode, IPCNode, ProcessNode, ProcessState, SubjectNode, IGraphNode
from se.sepolicygraph import Class2, PolicyGraph
from utils.logger import Logger
from setools.policyrep import Context, Type

OBJ_COLOR_MAP: Dict[str, str] = {
    'subject' : '#b7bbff',
    'subject_group' : 'white',
    'file' : 'grey',
    'ipc' : 'pink',
    'socket' : 'orange',
    'unknown' : 'red',
}

AllowEdge = Dict[str, Union[str, List[str]]]

class FileSystemInstance:
    '''巨型类，可以理解为一个实际运行的文件系统的实例'''
    def __init__(self, sepol: PolicyGraph, init: AndroidInit, file_contexts: List[AndroidFileContext]):
        self.sepol: PolicyGraph = sepol
        self.init: AndroidInit = init
        self.file_contexts: List[AndroidFileContext] = file_contexts
        '''从file_contextx文件中读取的文件context'''

        self.file_mapping: Dict[str, Dict[str, FilePolicy]] = {}
        '''type -> filename 反向映射'''

        # # Mixed instantiation
        self.subjects: Dict[str, SubjectNode] = {}
        '''所有实例化的主体， 使用type名进行索引'''

        self.subject_groups: Dict[str, SubjectNode] = {}
        '''所有process可能有的其他attribute, 使用attr名进行索引'''

        self.domain_attributes: List[str] = []
        '''所有process所可能拥有的 attribute'''

        self.objects: Dict[str, GraphNode] = {}
        '''所有object，使用obj_node_name名进行索引'''

        self.processes: Dict[str, ProcessNode] = {}
        '''Fully instantiated graph'''

    def instantiate(self) -> bool:
        """
        Recreate a running system's state from a combination of MAC and DAC policies.
            * Inflate objects into subjects (processes) if they can be executed
            * Instantiate files, IPC primitives,
            * Link subjects together through objects

        Namespaces:
         - subject
         - process
         - object
            * file
            * ipc
            * socket
        """

        Logger.debug("Applying file contexts to VFS...")

        # All files contain all of the metadata necessary to go forward
        self.apply_file_contexts()

        Logger.debug("Inflating subjects...")
        self.inflate_subjects()

        Logger.debug("Generating subject type hierarchy...")
        self.recover_subject_hierarchy()

        Logger.debug("Inflating subject dataflow graph...")
        self.inflate_graph()

        Logger.debug("Extracting policy capability bounds to subjects...")
        self.extract_selinux_capabilities()

        Logger.debug("Assigning conservative trust flag...")
        self.assign_trust()

        Logger.debug("Generating a process tree...")
        self.gen_process_tree()

        Logger.debug("Simulating process permissions...")
        if not self.simulate_process_permissions():
            return False
        
        self.stats()

        Logger.info("Finished instantiating SEPolicy")
        return True

    def apply_file_contexts(self):
        '''恢复文件系统中的标签'''
        recovered_labels = 0
        dropped_files: List[str] = []
        # 遍历文件系统中的所有文件 file 是一个文件路径
        for file in self.init.asp.combined_fs.files:
            label_from_file_context: bool = True    # 假设能够从file_context中获取到label
            fcmatches: List[AndroidFileContext] = self.get_file_context_matches(file)

            # XXX 没有匹配的文件context，或者文件是一个挂载点
            if len(fcmatches) == 0 or file in self.init.asp.combined_fs.mount_points:
                genfs_matches: List[Tuple[str, str, Context]] = []
                # 遍历所有的挂载点，验证该文件是否是挂载的文件系统中的文件
                for mount_path, mp in self.init.asp.combined_fs.mount_points.items():
                    if file.startswith(mount_path):
                        relfs : str = file[len(mount_path):]
                        fstype: str = mp.type
                        if relfs == "": relfs = "/"
                        if fstype in self.sepol.genfs:  # 如果是挂载的文件系统，那么就要找到对应的genfscon
                            for genfscon in self.sepol.genfs[fstype]:
                                if re.match(r'^' + genfscon.path + r'.*', relfs):
                                    genfs_matches += [(mount_path, genfscon.path, genfscon.context)]
                                pass
                        elif fstype in self.sepol.fs_use:
                            if fstype != "tmpfs": continue  # 目前只处理tmpfs
                            genfs_matches += [(mount_path, '/', self.sepol.fs_use[fstype].context)]
                if len(genfs_matches) == 0:
                    if self.init.asp.combined_fs.files[file].selinux is None:   # 寄
                        dropped_files.append(file)
                        Logger.warn("No file context for %s" % file)
                        continue    # 下一个文件
                    else:
                        primary_match: SELinuxContext = self.init.asp.combined_fs.files[file].selinux
                    pass
                else:  # 生成了新的label
                    genfs_matches = sorted(genfs_matches, reverse=True, key=lambda x: x[1])
                    primary_path: str = genfs_matches[0][0]
                    primary_match: SELinuxContext = SELinuxContext.FromString(str(genfs_matches[0][2]))
                    label_from_file_context = False
                    pass
            else:   # 有在file context中匹配
                ''' 在file_contexts文件中找到了匹配的文件context 找出最长的匹配
                [AndroidFileContext<^/odm/etc/permissions(/.*)?$ -> u:object_r:odm_xml_file:s0>,
                AndroidFileContext<^/(odm|vendor/odm)/etc(/.*)?$ -> u:object_r:vendor_configs_file:s0>,
                AndroidFileContext<^/(odm|vendor/odm)(/.*)?$ -> u:object_r:vendor_file:s0>]
                '''
                max_prefix_len: int = 0
                for afc in fcmatches:
                    r = re.compile(r"\.|\^|\$|\?|\*|\+|\||\[|\(|\{")    # 一些通配符
                    regex = afc.regex.pattern[1:len(afc.regex.pattern) - 1] # 去掉开头的^和结尾的$
                    pos = r.search(regex)   # 找到第一个通配符的位置
                    cur_prefix_len = pos.span()[0] if pos else len(regex)
                    if cur_prefix_len >= max_prefix_len:
                        max_prefix_len = cur_prefix_len
                        primary_match = afc.context

                pass
            
            # 如果原先没有context
            if self.init.asp.combined_fs.files[file].selinux is None:
                self.init.asp.combined_fs.files[file].selinux = primary_match
                recovered_labels += 1
            elif self.init.asp.combined_fs.files[file].selinux != primary_match:
                if label_from_file_context: # file_context本身和文件系统的冲突
                    # Logger.warn("File context %s does not match file system context %s" % (primary_match, self.init.asp.combined_fs.files[file].selinux))
                    pass
                else:
                    recovered_labels += 1
                    self.init.asp.combined_fs.files[file].selinux = primary_match

        for fn in dropped_files:
            del self.init.asp.combined_fs.files[fn]
            pass
        if len(dropped_files) > 0:
            Logger.warn("Dropped %d files with no file context" % len(dropped_files))
            pass
        Logger.info("Recovered %d file labels from file contexts" % recovered_labels)
        
    def get_file_context_matches(self, filename: str) -> List[AndroidFileContext]:
        '''返回所有匹配的文件context，选最长的那个'''
        matches: List[AndroidFileContext] = []

        for afc in self.file_contexts:
            # TODO: match on directory vs. plain file, etc.
            if afc.match(filename):
                matches += [afc]

        # heuristic: choose longest string as most specific match
        return sorted(matches, reverse=True, key=lambda x: x.regex.pattern)
    
    def is_attribute(self, attr: str) -> bool:
        return attr in self.sepol.attributes

    def expand_attribute(self, attr: str) -> List[str]:
        '''将attr展开为type'''
        if self.is_attribute(attr):
            return self.sepol.attributes[attr]
        else:
            return [attr]

    def inflate_subjects(self):
        '''提取所有能成为process的type，inflate 为 subject'''
        G: nx.MultiDiGraph = self.sepol.G_allow

        # 所有拥有  domain attribute 的 type 的所属的所有 attribute
        domain_attributes: Set[str] = set()

        # attribute domain collects All types used for processes.
        for process_type in self.sepol.attributes['domain']:    # 遍历 `domain` attribute 中的所有 type
            s: SubjectNode = SubjectNode(Cred())                # 创建一个新的subject
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % process_type)

            assert process_type not in self.subjects        # duplicate
            assert process_type not in self.sepol.aliases   # not an alias
            
            self.subjects[process_type] = s

            # 该process_type的所有attribute
            domain_attributes |= set(self.sepol.types[process_type])

        # Make sure not to include any attributes that have objects too!
        effective_attr: List[str] = []
        for attr in domain_attributes:  # 遍历拥有domain attr的所有type的所有attr
            no_effect = False
            assert attr not in self.sepol.types
            if attr not in G:   # 没有允许的规则，无效的attr，不产生影响
                continue
            for type in self.expand_attribute(attr):
                if type not in self.subjects:   # 这个type不在domain域中
                    no_effect = True
                    break
            if not no_effect:
                effective_attr += [attr]
            
        self.domain_attributes = effective_attr

        for attr in self.domain_attributes:
            s: SubjectNode = SubjectNode(Cred())
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % attr)
            assert attr not in self.subject_groups
            assert attr not in self.subjects
            self.subject_groups[attr] = s
            
    def gen_file_mapping(self):
        """set file_mapping
        Create an index of SELinux types to filesystem objects that we know about
        from our metadata extraction. Note, not all types in the graph will have this
        available. We assume files can only have a single type for their lifetime.
        A different typed file, even with the same path, would be considered a different file.
        """
        G = self.sepol.G_allow
        # associate relevant types with known files
        for file in self.init.asp.combined_fs.files:
            sid = self.init.asp.combined_fs.files[file].selinux
            # dereference alias as those nodes dont exist
            ty: str = self.sepol.types[sid.type] if sid.type in self.sepol.aliases else sid.type
            if ty not in G:
                continue
            if ty not in self.file_mapping:
                self.file_mapping[ty] = {}  # touch
            # associate a SID (ty) with a file (f) and its (perm)issions
            self.file_mapping[ty][file] = self.init.asp.combined_fs.files[file]

    def recover_subject_hierarchy(self):
        '''遍历type_transition allow rule, 为每个subject设置find_associated_files'''
        G_allow = self.sepol.G_allow
        Gt = self.sepol.G_transition

        self.gen_file_mapping()

        # Now we have scattered the files to their respective SEPolicy types
        #  * We need to link domains to their underlying executables

        # type_transition ITouchservice crash_dump_exec:process crash_dump;
        type_transition_classes: Dict[Tuple[str, str, int], str] = nx.get_edge_attributes(Gt, 'teclass') # :process
        domain_transitions: Dict[Tuple[str, str, int], str] = { k:v for k,v in type_transition_classes.items() if v == "process" }
        Logger.info("Back-propagating %d domain transitions", len(domain_transitions))

        # Used to track which domains didn't even have a `process type_transition` rule allowed
        has_backing_file_transition: Set[str] = set()

        ## Back propagate executable files to domain
        parent: str # source 
        child: str  # target
        e: int
        for (parent, child, e) in domain_transitions:       # each `type_transition` rule
            attrs: Dict[str, str] = Gt[parent][child][e]    # {'teclass': 'process', 'through': 'crash_dump_exec', 'name': None}
            object_type: str = attrs["through"]             # 必然有 through 属性

            has_backing_file_transition |= set([child])
            if object_type not in self.file_mapping:
                # This means we didn't find any backing file for this subject on the filesystem image
                # This can mean we're missing files OR that these subjects do not have an explicitly defined
                # domain to executable file transition.
                Logger.debug('Nothing to back propagate %s', object_type)
                continue
            # Build the process hierarchy
            self.subjects[parent].children |= set([self.subjects[child] ])
            self.subjects[child].parents   |= set([self.subjects[parent]])

            # Map the found files to the domain
            self.subjects[child].associate_file(self.file_mapping[object_type])
        
        ## Recover dyntransitions for the process tree 注意这个是allow 的规则中的允许,但并不是自动转换
        for subject_name, subject in self.subjects.items():             # 遍历所有的subject
            for child in G_allow[subject_name]:                         # each `allow` rule for type `subject_name`
                for _, edge in G_allow[subject_name][child].items():    # 遍历所有的edge
                    if edge["teclass"] == "process" and \
                        ("dyntransition" in edge["perms"] or "transition" in edge["perms"]) and subject_name != child:
                        # We may have already caught this during the file mapping, but that's why we're dealing with sets
                        for c in self.expand_attribute(child):
                            subject.children         |= set([self.subjects[c]])
                            self.subjects[c].parents |= set([subject])

        ## Special cases
        ##
        ##  1. init - first process created. may not have an explicit transition due to selinux loading time
        init_files = self.subjects["init"].backing_files    # `type init, domain, mlstrustedsubject;`
        
        if len(init_files) == 0:
            Logger.warn("init subject had no associated files")
            self.subjects["init"].associate_file({ "/init" : self.init.asp.combined_fs.files["/init"] })

        ##  2. system_server - forked from zygote, assigned fixed permissions. Runs as a platform app (java based), so no executable
        # Samsung sepolicys may lead to system_server having /system/bin/tima_dump_log as the system_server file. This is an abuse...
        system_server_files = self.subjects["system_server"].backing_files

        for fn, f in system_server_files.items():
            Logger.warning("system_server already has '%s' associated with it. Odd...", fn)

        # Drop any backing files as we only care about the daemon system_server, not weird dyntransitions
        self.subjects["system_server"].backing_files = {}

        ##  3. zygote - forked from init, assigned fixed permissions
        # zygote children that have no known files are likely app based. Associate app_process files with them
        zygote_files = self.subjects["zygote"].backing_files
        # '/system/bin/app_process32': /home/u/BiggerMAC/firmwares_mnt/Huawei_Mate_20/system/system/bin/app_process32
        if len(zygote_files) == 0:
            raise ValueError("zygote has no associated files")
        
        # Propagate zygote backed files to its children (zygote just forks, not execs, itself into children)
        # http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/jni/com_android_internal_os_Zygote.cpp#487
        for s in self.subjects["zygote"].children:   
            if len(s.backing_files) == 0:   # Don't give zygote files to subjects that already have some
                s.associate_file(zygote_files)

        ##  4. Final chance for file recovery (heuristic)
        no_backing_file_transitions = set(list(self.subjects)) - has_backing_file_transition
        # exclude the obvious app domain
        no_backing_file_transitions -= set(self.expand_attribute('appdomain'))

        # Okay, we have a list of domains that were clearly from dyntransitions
        # We have no mapping from them to their executable. Perform a last ditch search
        for domain in no_backing_file_transitions:
            # an earlier special case found something
            if len(self.subjects[domain].backing_files) > 0:
                continue

            found_files = self.init.asp.combined_fs.find('*' + domain)

            if len(found_files) == 1:
                fsp =  self.init.asp.combined_fs[found_files[0]]
                Logger.info("Last ditch file mapping recovery for %s found '%s'", domain, found_files[0])
                self.subjects[domain].associate_file({found_files[0]: fsp})
            else:
                Logger.info("Can not find associate file for domain '%s'", domain)

    def get_object_node(self, edge: AllowEdge) -> GraphNode:
        '''allow rule {'teclass': 'lnk_file', 'perms': ['getattr']}'''
        teclass: str = edge["teclass"]
        cls: Class2 = self.sepol.classes[teclass]
        node = None
        
        if cls.inherits is not None:
            match cls.inherits:
                case "file":
                    node = FileNode()
                case "socket":
                    node = IPCNode("socket")
                case "ipc":
                    node = IPCNode(teclass)
                case "cap" | "cap2":
                    node = SubjectNode(Cred())
        else:
            match teclass:
                case 'drmservice'| 'debuggerd'| 'property_service'| 'service_manager'| 'hwservice_manager'| \
                    'binder'| 'key'| 'msg'| 'system'| 'security'| 'keystore_key'| 'zygote'| 'kernel_service':
                    node = IPCNode(teclass)
                case 'netif'| 'peer'| 'node':
                    node = IPCNode("socket")
                case 'filesystem':
                    node = FileNode()
                case "cap_userns"| "cap2_userns"| "capability"| "capability2"| "fd":
                    node = SubjectNode(Cred())
                case 'process':
                    node = IPCNode("process_op")
                case 'bpf':
                    node = SubjectNode(Cred())

        
        if node is None:
            raise ValueError("Unhandled object type %s" % teclass)

        return node

    def get_dataflow_direction(self, edge: AllowEdge) -> Tuple[bool, bool, bool]:
        # We consider binder:call and *:ioctl to be bi-directional

        # ignore fd:use for now
        # we ignore getattr as this is not security sensitive enough
        # ignore DRMservice for now (pread)
        read_types = [
            'read', 'ioctl', 'unix_read', 'search',
            'recv', 'receive', 'recv_msg',  'recvfrom', 'rawip_recv', 'tcp_recv', 'dccp_recv', 'udp_recv',
            'nlmsg_read', 'nlmsg_readpriv',
            # Android specific
            'call', # binder
            'list', # service_manager
            'find', # service_manager
        ]

        # ignore setattr for now. ignore create types
        write_types = [
            'write', 'append',
            #'ioctl',
            'add_name', 'unix_write', 'enqueue',
            'send', 'send_msg',  'sendto', 'rawip_send', 'tcp_send', 'dccp_send', 'udp_send',
            'connectto',
            'nlmsg_write',
            # Android specific
            'call', # binder
            #'transfer', # binder
            'set', # property_service
            'add', # service_manager
            'find', # service_manager - this is not necessarily a write type,
                    #but why bother finding a service if you aren't going to send a message to it?
            'ptrace',
            'transition',
        ]

        # management types
        manage_types = [
            'create', 'open'
        ]

        teclass: str = edge["teclass"]
        perms: List[str] = edge["perms"]

        has_read: bool = False
        has_write: bool = False
        has_manage: bool = False

        for perm in perms:
            if perm in write_types:
                has_write = True
            if perm in read_types:
                has_read = True
            if perm in manage_types:
                has_manage = True

        return has_read, has_write, has_manage

    def inflate_graph(self, expand_all_objects: bool = True, skip_fileless_subjects: bool = True):
        """
        Create all possible subjects and objects from the MAC policy and link
        them in a graph based off of dataflow.
        """
        G_allow = self.sepol.G_allow
        Gt = self.sepol.G_transition

        G_dataflow = self.sepol.G_dataflow
        for s in self.subjects.values():    # add all SubjectNode s
            if skip_fileless_subjects and len(s.backing_files) == 0:
                continue
            G_dataflow.add_node(s.get_node_name(), obj=s, fillcolor=OBJ_COLOR_MAP['subject'])

        for attr in self.subject_groups:    # add all SubjectGroupNode s
            s = self.subject_groups[attr]
            G_dataflow.add_node(s.get_node_name(), obj=s, fillcolor=OBJ_COLOR_MAP['subject_group'])

            for domain in self.expand_attribute(attr):
                assert domain in self.subjects

                if skip_fileless_subjects and len(self.subjects[domain].backing_files) == 0:
                    continue

                # add a is-a edge between the subjects as they are effectively the same
                G_dataflow.add_edge(self.subjects[domain].get_node_name(), s.get_node_name())
        
        for subject_name in list(self.subjects.keys()) + list(self.subject_groups.keys()):
            subject: SubjectNode = self.subjects[subject_name] if subject_name in self.subjects else self.subject_groups[subject_name]
            if subject.get_node_name() not in G_dataflow:
                Logger.info("Skipping subject %s as it has no backing files", subject_name)
                continue
            for obj_name in G_allow[subject_name]:
                for edge in G_allow[subject_name][obj_name].values():
                    ###### Create object
                    obj: GraphNode = self.get_object_node(edge)
                    df_r, df_w, df_m = self.get_dataflow_direction(edge)
                    obj_type = obj.get_obj_type()
                    
                    # mostly ignore subject nodes as the target for other subjects
                    if obj_type == "subject":
                        match edge["teclass"]:
                            case "fd" | "process" | "bpf" | "capability" | "capability2" | "cap_userns" | "cap2_userns":
                                continue
                            case _:
                                raise ValueError("Ignoring MAC edge <%s> -[%s]-> <%s>" % (subject_name, edge["teclass"], obj_name))
                    domain_name: str = subject.get_node_name()

                    object_expansion: List[str] = self.expand_attribute(obj_name) if expand_all_objects else [obj_name]
                    
                    for ty in object_expansion:
                        new_obj: IGraphNode = copy.deepcopy(obj)
                        new_obj.sid = SELinuxContext.FromString("u:object_t:%s:s0" % ty)
                        obj_type = new_obj.get_obj_type()
                        if obj_type == "ipc":
                            if ty in self.subjects:
                                new_obj: IPCNode
                                new_obj.owner = self.subjects[ty]
                            else:
                                if new_obj.ipc_type.endswith("service_manager"):
                                    found_ipc_owner = False
                                    for source, target in G_allow.in_edges(self.actualize(new_obj.sid.type)):
                                        obj_edge: AllowEdge
                                        for obj_edge in G_allow[source][target].values():
                                            # find any that have the add permission
                                            if "add" in obj_edge["perms"]:
                                                # expand - hal_graphics_allocator_server 9.0
                                                # XXX: just take the first owner we see...
                                                source_type = self.expand_attribute(source)[0]

                                                new_obj.owner = self.subjects[source_type]

                                                found_ipc_owner = True
                                                break
                                        if found_ipc_owner:
                                            break
                                        pass
                                elif new_obj.ipc_type == "property_service":
                                    new_obj.owner = self.subjects["init"]
                            # seriously, there is no point in adding this if there is no owner
                            # we'd be yelling to no one
                            if not new_obj.owner:
                                continue

                            if len(new_obj.owner.backing_files) == 0 and skip_fileless_subjects:
                                assert isinstance(new_obj.owner, SubjectNode)
                                continue

                            assert new_obj.owner.sid is not None
                        if not df_r and not df_w:   # no read or write, skip
                            continue
                        if obj_type == "file":
                            if ty in self.file_mapping:
                                new_obj.associate_file(self.file_mapping[ty])
                        obj_node_name = new_obj.get_node_name()

                        # objects may be seen more than once, hence they need unique names
                        self.objects[obj_node_name] = new_obj

                        # create object
                        G_dataflow.add_node(obj_node_name, obj=new_obj, fillcolor=OBJ_COLOR_MAP[obj_type])

                        # We assume there is no way for subjects to talk directly (except shared memory)
                        # data flow: object -> subject (read)
                        if df_r and domain_name not in G_dataflow[obj_node_name]:
                            G_dataflow.add_edge(obj_node_name, domain_name, ty="read", color='red')

                        # data flow: subject -> object (write)
                        if df_w or df_m:
                            if obj_node_name in G_dataflow[domain_name]:
                                # {'ty': 'write', 'color': 'green'}
                                edge_types = list(map(lambda x: x['ty'], G_dataflow[domain_name][obj_node_name].values()))
                            else:
                                edge_types = []

                            if df_w and 'write' not in edge_types:
                                G_dataflow.add_edge(domain_name, obj_node_name, ty="write", color='green')
        return
    
    def actualize(self, ty: str):
        """
        Transforms a type into itself and all its attributes
        """
        assert not self.is_attribute(ty)
        # dereference alias as those nodes dont exist
        ty = self.sepol.types[ty] if ty in self.sepol.aliases else ty
        return self.sepol.types[ty] + [ty]

    def extract_selinux_capabilities(self):
        '''add selinux capabilities to subjects'''
        G_allow = self.sepol.G_allow
        for subject_name, subject in self.subjects.items():
            for obj_name in G_allow[subject_name]:
                for edge in G_allow[subject_name][obj_name].values():
                    edge: AllowEdge
                    if edge["teclass"] not in ["capability", "capability2"]:
                        continue
                    if subject_name != obj_name:
                        # G_allow['aptouch_daemon']['vendor_logcat_data_file']
                        Logger.critical("SELinux capability edge <%s> -[%s]-> <%s> is not self-referential" % (subject_name, edge["teclass"], obj_name))
                    for cap in edge["perms"]:
                        subject.cred.cap.add("selinux", cap)

    def assign_trust(self):
        for name, subject in self.subjects.items():
            trusted: bool = False
            reason: str = ""

            ty: str = subject.sid.type

            if ty in ['init', 'vold', 'ueventd', 'kernel', 'system_server']:
                trusted = True
                # https://source.android.com/security/overview/updates-resources#triaging_bugs
                reason = "in Android's TCB"
            if trusted:
                subject.trusted = True
                Logger.debug("Subject %s is trusted (reason: %s)", name, reason)

        for name, obj in self.objects.items():
            trusted = False
            reason = ""

            for fn in obj.backing_files:
                for magic in ['/sys/', '/dev/']:
                    if fn.startswith(magic):
                        trusted = True
                        reason = "backing file %s starts with %s" % (fn, magic)
                        break
            
            # revoke trust from some externally controlled sources
            for fn, fo in obj.backing_files.items():
                if not hasattr(fo, "tags"):
                    fo.tags = set()
                if fn.startswith('/dev/'):
                    for pattern in ["*usb*", "*GS*", "*serial*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo.tags |= set(['usb'])
                            break

                    for pattern in ["*bt_*", "*bluetooth*", "*hci*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo.tags |= set(['bluetooth'])
                            break

                    for pattern in ["*nfc*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo.tags |= set(['nfc'])
                            break

                    for pattern in ["*at_*", "*atd*", "*modem*", "*mdm*", "*smd*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo.tags |= set(['modem'])
                            break
            
            if trusted:
                obj.trusted = True
                Logger.debug("Object %s is trusted (reason: %s)", name, reason)

    def gen_process_tree(self):
        """
        Take the existing subject hierarchy and fully instantiate it.
        This means expand out one of every backing file for a subject into a potential running
        process. Whether or not the process is actually running will be decided during boot
        simulation.
        """
        # Start from the top of hierarchy
        kernel_subject = self.subjects["kernel"]
        init_subject = self.subjects["init"]
        visited: Set[SubjectNode] = set()

        # Technically the kernel can have a ton of processes, but we only consider one in our graph
        self.processes["kernel_0"] = ProcessNode(kernel_subject, None, {'/kernel' : {}}, 0)

        # (parent: ProcessNode, child: SubjectNode)
        stack = [(self.processes["kernel_0"], init_subject)]

        ### Propagate subject permissions by simulating fork/exec
        # Depth-first traversal
        pid = 1

        while len(stack):   # child_subject 为当前遍历的parent
            parent_process, child_subject = stack.pop()
            visited |= set([child_subject])

            for fn, fp in child_subject.backing_files.items():  # 对于属于这个type所拥有的所有文件，单独实例化为进程
                fn = self.init.asp.combined_fs.real_path(fn)
                new_process = ProcessNode(child_subject, parent_process, {fn : fp}, pid)
                parent_process.add_child(new_process)
                proc_id = "%s_%d" % (child_subject.type, pid)
                
                assert proc_id not in self.processes
                self.processes[proc_id] = new_process

                pid += 1

                for child in sorted(child_subject.children, key=lambda x: str(x.type)):
                    if child not in visited or (child.type == "crash_dump" and child_subject.type in ["zygote"]):
                        stack += [(new_process, child)]

    def simulate_process_permissions(self):
        # Special cases for android
        kernel = self.processes["kernel_0"]
        init = self.processes["init_1"] # init 进程

        ## technically the kernel is a member of all groups, but we dont care for this case
        kernel.cred.uid = kernel.cred.gid = 0
        kernel.cred.clear_groups()
        kernel.cred.cap.grant_all()
        kernel.state = ProcessState.RUNNING
        kernel.cred.sid = kernel.subject.sid

        ## init has everything too
        init.cred.uid = init.cred.gid = 0
        init.cred.sid = init.subject.sid

        # Android 7.0+ - hidepid=2 introduced
        if self.init.asp.get_android_version()[0] >= 7:
            init.cred.add_group('readproc')
        else:
            init.cred.clear_groups()

        init.cred.cap.grant_all()
        init.state = ProcessState.RUNNING

        system_server_parent = None

        for init_child in sorted(init.children, key=lambda x: x.pid):   # for each init child process
            init_child.cred = init.cred.execve(init_child.subject.sid)
            init_child.cred.clear_groups()  # Drop any supplemental groups from init
            
            found_service = None
            # (a,_),*_={1:1, 2:2, 3:3}.items()
            (exe_path, _), = init_child.exe.items()   # only one element ? otherwise raise exception 
            for service in self.init.services.values(): # 遍历所有的init service
                cmd = self.init.asp.combined_fs.real_path(service.args[0])
                if cmd not in self.init.asp.combined_fs.files:
                    continue
                if cmd == exe_path and not service.oneshot:
                    if found_service:
                        continue
                    found_service = service
            if not found_service:
                Logger.warn("Not find service definition for %s", init_child)
                continue
            init_child.state = ProcessState.RUNNING
            service: AndroidInitService = found_service
            Logger.debug("Got service definition for %s: %s", init_child, service)
            if service.cred.uid: init_child.cred.uid = service.cred.uid
            if service.cred.gid: init_child.cred.gid = service.cred.gid
            if service.cred.groups:
                for group in service.cred.groups:
                    init_child.cred.add_group(group)

            if service.cred.sid and init_child.cred.sid != service.cred.sid:
                Logger.warning("Service definition for %s has different sid (%s)", init_child.sid.type, service.cred.sid)
            if init_child.cred.uid != 0: init_child.cred.cap.drop_all()
            if len(service.cred.cap.ambient):
                Logger.info("Service %s has ambient capabilities %s", init_child.sid.type, service.cred.cap.ambient)
                init_child.cred.cap.drop_all()
                init_child.cred.cap.permitted = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.effective = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.bounding = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.inherited = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.ambient = copy.deepcopy(service.cred.cap.ambient)
            args = service.args

            # Zygote special case handling
            if "app_process" in args[0]:
                if "--start-system-server" in args:
                    if system_server_parent is not None:
                        Logger.error("Found multiple system_server parents!")
                        continue

                    system_server_parent = init_child
                    Logger.info("Primary system_server parent: %s", init_child)
        # Handle the special case of native daemons spawning additional processes (except for zygote)
        for init_child in sorted(list(init.children), key=lambda x: x.pid):
            if init_child.state == ProcessState.STOPPED and "zygote" not in init_child.subject.sid.type:
                for possible_parent in list(init.children):
                    if possible_parent.state == ProcessState.RUNNING:
                        if possible_parent.subject == init_child.subject:
                            Logger.warn("Reparenting %s -> %s", init_child, possible_parent)

                            possible_parent.children |= set([init_child])
                            init.children -= set([init_child])
                            init_child.parent = possible_parent

                            # refork from the new parent creds
                            init_child.cred = possible_parent.cred.execve()
                            init_child.state = ProcessState.RUNNING
                            break
        if not system_server_parent:
            from IPython import embed; embed(); exit(1)
            Logger.error("Failed to identify the system_server parent")
            return False
        
        zygotes = sorted(list(filter(lambda x: "zygote" in x.subject.sid.type, init.children)), key=lambda x: x.pid)

        # remove children from all zygotes with differing executables
        for zyg in zygotes:
            (z_fn, _), = zyg.exe.items()
            if system_server_parent != zyg:
                zyg.children = set(filter(lambda x: x.subject.sid.type != "system_server", zyg.children))
                Logger.info("Dropping system_server from %s", zyg)
            for child in list(zyg.children):
                (exe_path, _), = child.exe.items()

                if exe_path != z_fn and "crash" not in exe_path:
                    zyg.children -= set([child])
        # spawn an untrusted app
        if len(zygotes) > 0:
            app_parent = zygotes[0]
            untrusted_apps = list(filter(lambda x: "untrusted_app" in x.subject.sid.type, app_parent.children))
            crash_dump = list(filter(lambda x: "crash_dump" in x.subject.sid.type, app_parent.children))
            app_id = 0

            for crashes in sorted(crash_dump, key=lambda x: x.subject.sid.type):
                crashes.cred = app_parent.cred.execve(new_sid=crashes.subject.sid)
                crashes.state = ProcessState.RUNNING
                Logger.info("Spawned crash_dump %s from %s", repr(crashes), repr(app_parent))

            for primary_app in sorted(untrusted_apps, key=lambda x: x.subject.sid.type):
                primary_app.cred = app_parent.cred.execve(new_sid=primary_app.subject.sid)
                # Drop any supplemental groups from init
                primary_app.cred.clear_groups()
                primary_app.cred.cap.drop_all()

                primary_app.cred.uid = 10000+app_id
                primary_app.cred.gid = 10000+app_id
                primary_app.cred.add_group('inet')
                primary_app.cred.add_group('everybody')
                primary_app.cred.add_group(50000+app_id)
                primary_app.state = ProcessState.RUNNING
                Logger.info("Spawned untrusted_app %s from %s", repr(primary_app), repr(app_parent))
                app_id += 1
        else:
            Logger.error("No zygotes! This is bad")
            return False
        system_server = list(filter(lambda x: x.subject.sid.type == "system_server", system_server_parent.children))
        if len(system_server) == 0:
            Logger.error("Issue spawning system_server")
            return False
        else:
            system_server = system_server[0]
        ## system_server
        # See system server permissions: http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/java/com/android/internal/os/ZygoteInit.java#646
        system_server.cred.uid = 1000
        system_server.cred.gid = 1000
        system_server.cred.sid = system_server.subject.sid

        system_server.cred.cap.bound_none()

        for cap in ['CAP_IPC_LOCK', 'CAP_KILL', 'CAP_NET_ADMIN', 'CAP_NET_BIND_SERVICE', 'CAP_NET_BROADCAST', 'CAP_NET_RAW',
                'CAP_SYS_MODULE', 'CAP_SYS_NICE', 'CAP_SYS_PTRACE', 'CAP_SYS_TIME', 'CAP_SYS_TTY_CONFIG', 'CAP_WAKE_ALARM']:
            system_server.cred.cap.add('inherited', cap)
            system_server.cred.cap.add('effective', cap)
            system_server.cred.cap.add('permitted', cap)
        for group in [1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1032,3001,3002,3003,3006,3007,3009,3010]:
            system_server.cred.add_group(group)

        system_server.state = ProcessState.RUNNING

        return True

    def stats(self):
        log = Logger
        log.info("------- STATS --------")
        log.info("---[File Contexts Report]---")
        self.file_contexts_report()

        ############################

        log.info("---[Subject Backing File Report]---")
        subjects_without_backing_files = list(filter(lambda x: len(x[1].backing_files) == 0, self.subjects.items()))
        subjects_with_backing_files = list(filter(lambda x: len(x[1].backing_files) > 0, self.subjects.items()))
        objects_without_backing_files = list(filter(lambda x: len(x[1].backing_files) == 0, self.objects.items()))
        objects_with_backing_files = list(filter(lambda x: len(x[1].backing_files) > 0, self.objects.items()))

        log.info("STAT: Dataflow created %d subjects and %d objects with a total of %d R/W edges",
                len(self.subjects), len(self.objects),
                len(self.sepol.G_dataflow.edges()))
        log.info("STAT: Recovered subject %d (%.1f%%) file mappings, but unable to do so for %d subjects",
                 len(subjects_with_backing_files),
                 float(len(subjects_with_backing_files))/len(self.subjects)*100.0,
                 len(subjects_without_backing_files))
        log.info("STAT: Recovered object %d (%.1f%%) file mappings, but unable to do so for %d objects",
                 len(objects_with_backing_files),
                 float(len(objects_without_backing_files))/len(self.objects)*100.0,
                 len(objects_without_backing_files))

        ############################

        log.info("---[IPC REPORT]---")

        # IPC Missing owner report
        missing_owner = set()
        got_owner = set()
        missing_ipc_types = {}
        ipc_type_cnt = {}

        for on, o in self.objects.items():
            if isinstance(o, IPCNode):
                ipc_type_cnt[o.ipc_type] = ipc_type_cnt.get(o.ipc_type, 0) + 1

                if not o.owner:
                    missing_owner |= set([o])
                    missing_ipc_types[o.ipc_type] = missing_ipc_types.get(o.ipc_type, 0) + 1
                else:
                    got_owner |= set([o])

        log.info("IPC Freq:")
        for ty, freq in sorted(ipc_type_cnt.items(), key=lambda x: x[1], reverse=True):
            log.info("%s - %d (%.1f%%)", ty, freq, freq/(len(got_owner)+len(missing_owner))*100.0)

        log.info("%d/%d (%.2f%%) IPCNodes are missing their owners!",
                len(missing_owner), len(got_owner), float(len(missing_owner)) / len(got_owner) * 100.0)
        for ty, freq in sorted(missing_ipc_types.items()):
            log.info("IPC type '%s' missing %d owners", ty, freq)

        log.info("------- END STATS --------")

    def file_contexts_report(self):
        fc_found = set()
        fc_found_types = set()
        fc_missing_types = set()
        fc_prefixes = {}

        # get some qualitative data about the file_contexts in relation to the FS
        for f, perm in self.init.asp.combined_fs.files.items():
            matches: List[AndroidFileContext] = self.get_file_context_matches(f)

            if len(matches) <= 0: continue

            ty = perm.selinux.type
            fc_found |= set(matches)
            fc_found_types |= set([ty])

        # figure out which file contexts are missing from the file system
        missing = set(self.file_contexts) - fc_found

        for fc in missing:
            # which types are missing
            fc_missing_types.add(fc.context.type)
            prefix = fc.regex.pattern.split(os.path.sep)[1]
            if prefix not in fc_prefixes:
                fc_prefixes[prefix] = 1
            else:
                fc_prefixes[prefix] += 1

        fc_all_types = set(map(lambda x: x.context.type, self.file_contexts))

        log = Logger
        log.info("STAT: Filesystem matched %d/%d FCs (%.2f%% are missing)",
                len(fc_found), len(self.file_contexts), len(missing)/len(self.file_contexts)*100.0)
        log.info("Here's a list of the most common filesystem prefixes that were never found")
        for f, freq in sorted(fc_prefixes.items(), key=lambda x: x[1], reverse=True):
            if freq > 1:
                log.info("/%-10s - %d" % (f, freq))

        with open('missing-fc-report.txt', 'w') as report:
            for fc in sorted(missing, key=lambda _: _.regex.pattern):
                report.write(fc.regex.pattern + " " + fc.context.type + "\n")

pass

