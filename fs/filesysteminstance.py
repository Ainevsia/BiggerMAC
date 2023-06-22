import re
import networkx as nx
from typing import Dict, List, Set, Tuple
from android.dac import Cred
from android.init import AndroidInit
from android.sepolicy import SELinuxContext
from fs.filecontext import AndroidFileContext
from fs.filesystempolicy import FilePolicy
from se.graphnode import SubjectNode
from se.sepolicygraph import PolicyGraph
from utils.logger import Logger
from setools.policyrep import Context, Type

class FileSystemInstance:
    '''巨型类，可以理解为一个实际运行的文件系统的实例'''
    def __init__(self, sepol: PolicyGraph, init: AndroidInit, file_contexts: List[AndroidFileContext]):
        self.sepol = sepol
        self.init = init
        # 从file_contextx文件中读取的文件context
        self.file_contexts = file_contexts
        

        self.file_mapping: Dict[str, Dict[str, FilePolicy]] = {}
        '''type -> {filename -> FilePolicy}'''

        # # Mixed instantiation
        self.subjects: Dict[str, SubjectNode] = {}
        '''所有的主体 subject => SubjectNode， 使用type名进行索引'''

        self.subject_groups = {}
        '''???'''

        self.domain_attributes: List[str] = []
        '''所有的domain'''

        # self.objects = {}

        # # Fully instantiated graph
        # self.processes = {}

    def instantiate(self):
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


        pass

    def apply_file_contexts(self):
        recovered_labels = 0
        dropped_files: List[str] = []
        # 遍历文件系统中的所有文件 file 是一个文件路径
        for file in self.init.asp.combined_fs.files:
            label_from_file_context: bool = True    # 假设能够从file_context中获取到label
            fcmatches: List[AndroidFileContext] = self.get_file_context_matches(file)
            # if file == '/data':
            #     from IPython import embed; embed(); exit(1)
            # XXX 没有匹配的文件context，或者文件是一个挂载点 or -> and
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
                            pass
                        pass
                # if file == '/data':
                #     from IPython import embed; embed(); exit(1)
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
        '''检查是否是type还是attribute，如果是attribute，返回所有的type'''
        if self.is_attribute(attr):
            return self.sepol.attributes[attr]
        else:
            return [attr]

    def inflate_subjects(self):
        G: nx.DiGraph = self.sepol.G_allow
        G_subject = nx.MultiDiGraph()

        self.subject_groups = {}
        domain_attributes: Set[str] = set()

        for domain in self.sepol.attributes['domain']:  # 遍历 `domain` attribute 中的所有 type
            s: SubjectNode = SubjectNode(Cred())
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % domain)

            assert domain not in self.subjects, "Duplicate subject %s" % domain
            self.subjects[domain] = s

            # 拥有domain attribute的所有type的所有atrribute 集合
            attribute_membership: List[str] = self.sepol.types[str(domain)]

            domain_attributes |= set(attribute_membership)

            G_subject.add_node('domain', fillcolor='#f7bb00')
            G_subject.add_edge('domain', domain)
            # print(domain)
            pass

        # Make sure not to include any attributes that have objects too!
        good: List[str] = []
        for attr in sorted(list(domain_attributes)):
            bad = False
            for type in self.expand_attribute(attr):
                if type not in self.subjects:
                    bad = True
                    pass
                else:
                    if attr != "domain":
                        G_subject.add_node(attr, fillcolor='#b700ff')
                    G_subject.add_edge(attr, domain)
            if attr not in G:
                bad = True
                pass
            if not bad:
                good += [attr]
            pass
        
        self.domain_attributes = good

        for attr in self.domain_attributes:
            s = SubjectNode(Cred())
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % attr)
            assert attr not in self.subject_groups
            assert attr not in self.subjects
            self.subject_groups[attr] = s
        pass
    
    def gen_file_mapping(self):
        """
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
            ty = self.sepol.types[sid.type][0] if sid.type in self.sepol.aliases else sid.type
            if ty not in G:
                continue
            if ty not in self.file_mapping:
                self.file_mapping[ty] = {}  # touch
            # associate a SID (ty) with a file (f) and its (perm)issions
            self.file_mapping[ty][file] = self.init.asp.combined_fs.files[file]

            pass
        pass

    def recover_subject_hierarchy(self):
        '''恢复进程关系？还没完全能明白'''
        G = self.sepol.G_allow
        Gt = self.sepol.G_transition

        self.gen_file_mapping()

        # Now we have scattered the files to their respective SEPolicy types
        #  * We need to link domains to their underlying executables

        # type_transition ITouchservice crash_dump_exec:process crash_dump;
        type_transition_classes = nx.get_edge_attributes(Gt, 'teclass') # :process

        domain_transitions = { k:v for k,v in type_transition_classes.items() if v == "process" }
        Logger.info("Back-propagating %d domain transitions", len(domain_transitions))

        # Used to track which domains didn't even have a process type_transition
        has_backing_file_transition: Set[str] = set([])

        ## Back propagate executable files to domain
        parent: str
        child: str
        for (parent, child, e) in domain_transitions:
            attrs = Gt[parent][child][e]
            object_type: str = attrs["through"]

            has_backing_file_transition |= set([child]) # make a set ! set(child) :TypeError: 'int' object is not iterable
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
            # child_obj.associate_file(self.file_mapping[object_type]["files"])
            self.subjects[child].associate_file(self.file_mapping[object_type])
        
        ## Recover dyntransitions for the process tree
        for subject_name, subject in self.subjects.items():
            for child in G[subject_name]:
                for _, edge in G[subject_name][child].items():
                    if edge["teclass"] == "process" and \
                        ("dyntransition" in edge["perms"] or "transition" in edge["perms"]) and subject_name != child:
                        # We may have already caught this during the file mapping, but that's why
                        # we're dealing with sets
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
        if len(zygote_files) == 0:
            Logger.error("zygote subject has no associated files")
            raise ValueError("zygote has no associated files")
        
        # Propagate zygote backed files to its children (zygote just forks, not execs, itself into children)
        # http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/jni/com_android_internal_os_Zygote.cpp#487
        for s in self.subjects["zygote"].children:
            # Don't give zygote files to subjects that already have some
            if len(s.backing_files) == 0:
                for fn, f in zygote_files.items():
                    s.associate_file({fn:f})

        ##  4. Final chance for file recovery (heuristic)
        no_backing_file_transitions = set(list(self.subjects)) - has_backing_file_transition
        # exclude the obvious app domain
        no_backing_file_transitions -= set(self.expand_attribute('appdomain'))



        # Okay, we have a list of domains that were clearly from dyntransitions
        # We have no mapping from them to their executable. Perform a last ditch search
        for domain in sorted(list(no_backing_file_transitions)):
            # an earlier special case found something
            if len(self.subjects[domain].backing_files) > 0:
                continue

            found_files = self.init.asp.combined_fs.find('*' + domain)

            if len(found_files) == 1:
                # fsp =  self.init.asp.combined_fs[found_files[0]]
                Logger.info("Last ditch file mapping recovery for %s found '%s'", domain, found_files[0])
                self.subjects[domain].associate_file(found_files[0])
            else:
                Logger.info("Can not find associate file for domain '%s'", domain)


            from IPython import embed; embed(); exit(1)
        
        pass


    pass

pass

