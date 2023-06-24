
from typing import Dict, Set
from android.dac import Cred
from android.sepolicy import SELinuxContext
from fs.filesystempolicy import FilePolicy


class GraphNode:
    def get_obj_type(self):
        if isinstance(self, IPCNode):
            obj_type = "ipc"
        elif isinstance(self, SubjectNode):
            obj_type = "subject"
        elif isinstance(self, FileNode):
            obj_type = "file"
        elif isinstance(self, ProcessNode):
            obj_type = "process"
        else:
            raise ValueError("Unhandled generic object type %s" % repr(self))

        return obj_type
    
    def __repr__(self):
        return "<GraphNode[%s]>" % self.get_obj_type()
    

class FileNode(GraphNode):
    pass

class IPCNode(GraphNode):
    pass

class ProcessNode(GraphNode):
    pass


class SubjectNode(GraphNode):
    '''记录subject的父子关系'''
    def __init__(self, cred: Cred):
        super().__init__()
        self.parents : Set[SubjectNode] = set()
        self.children: Set[SubjectNode] = set()

        self.backing_files: Dict[str, FilePolicy] = {}
        '''拥有此type的实际的系统文件'''
        
        self.cred: Cred = cred
    
    @property
    def sid(self) -> SELinuxContext:
        return self.cred.sid
    
    @sid.setter
    def sid(self, v: SELinuxContext):
        self.cred.sid = v
    
    def associate_file(self, file_obj: Dict[str, FilePolicy]):
        '''set SubjectNode's backing_files'''
        self.backing_files.update(file_obj)

    def get_node_name(self) -> str:
        return "subject:%s" % (self.sid.type)


pass

