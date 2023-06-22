import re
from typing import List, Tuple
from android.init import AndroidInit
from fs.filecontext import AndroidFileContext
from se.sepolicygraph import PolicyGraph
from utils.logger import Logger
from setools.policyrep import Context

class FileSystemInstance:
    def __init__(self, sepol: PolicyGraph, init: AndroidInit, file_contexts: List[AndroidFileContext]):
        self.sepol = sepol
        self.init = init
        # 从file_contextx文件中读取的文件context
        self.file_contexts = file_contexts
        

        # self.file_mapping = {}

        # # Mixed instantiation
        # self.subjects = {}
        # self.subject_groups = {}
        # self.domain_attributes = []
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


        pass

    def apply_file_contexts(self):
        # TODO: need to refine this process according the real context initialization.
        for file in self.init.asp.combined_fs.files:
            matches: List[AndroidFileContext] = self.get_file_context_matches(file)
            if len(matches) == 0 or file in self.init.asp.combined_fs.mount_points:
                genfs_matches: List[Tuple[str, str, Context]] = []
                for mount_path, mp in self.init.asp.combined_fs.mount_points.items():
                    # 遍历所有的挂载点，验证该文件是否是挂载的文件系统中的文件
                    if file.startswith(mount_path):
                        relfs : str = file[len(mount_path):]
                        fstype: str = mp.type
                        if relfs == "": relfs = "/"
                        if fstype in self.sepol.genfs:  # 
                            for genfscon in self.sepol.genfs[fstype]:
                                if re.match(r'^' + genfscon.path + r'.*', relfs):
                                    genfs_matches += [(mount_path, genfscon.path, genfscon.context)]
                                pass

                            pass
                        pass
                pass
    
    def get_file_context_matches(self, filename: str) -> List[AndroidFileContext]:
        '''返回所有匹配的文件context，选最长的那个'''
        matches: List[AndroidFileContext] = []

        for afc in self.file_contexts:
            # TODO: match on directory vs. plain file, etc.
            if afc.match(filename):
                matches += [afc]

        # heuristic: choose longest string as most specific match
        return sorted(matches, reverse=True, key=lambda x: x.regex.pattern)