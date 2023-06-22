import re
import networkx as nx
from typing import Dict, List, Set, Tuple
from android.dac import Cred
from android.init import AndroidInit
from android.sepolicy import SELinuxContext
from fs.filecontext import AndroidFileContext
from se.graphnode import SubjectNode
from se.sepolicygraph import PolicyGraph
from utils.logger import Logger
from setools.policyrep import Context, Type

class FileSystemInstance:
    def __init__(self, sepol: PolicyGraph, init: AndroidInit, file_contexts: List[AndroidFileContext]):
        self.sepol = sepol
        self.init = init
        # 从file_contextx文件中读取的文件context
        self.file_contexts = file_contexts
        

        # self.file_mapping = {}

        # # Mixed instantiation
        self.subjects: Dict[str, SubjectNode] = {}
        '''所有的主体subject'''
        self.subject_groups = {}
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
                    Logger.warn("File context %s does not match file system context %s" % (primary_match, self.init.asp.combined_fs.files[file].selinux))
                else:
                    recovered_labels += 1
                    self.init.asp.combined_fs.files[file].selinux = primary_match
                pass

            pass

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

        

    pass

pass

