
from android.dac import Cred
from android.sepolicy import SELinuxContext


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
    def __init__(self, cred: Cred):
        super().__init__()
        self.parents = set()
        self.children = set()

        self.backing_files = {}
        self.cred: Cred = cred
    
    @property
    def sid(self) -> SELinuxContext:
        return self.cred.sid
    
    @sid.setter
    def sid(self, v: SELinuxContext):
        self.cred.sid = v
    
    pass


pass

