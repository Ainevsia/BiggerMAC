
from enum import Enum
from typing import Dict, Protocol, Self, Set, Union
from android.capabilities import Capabilities
from android.dac import Cred
from android.sepolicy import SELinuxContext
from fs.filesystempolicy import FilePolicy

class IGraphNode(Protocol):
    def sid() -> SELinuxContext: ...
    def get_obj_type(self) -> str: ...

class GraphNode:
    def __init__(self):
        self.backing_files: Dict[str, FilePolicy] = {}
        '''拥有此type的实际的系统文件'''

        self.trusted: bool = False
        '''是否是一个可信的subject'''

    def associate_file(self, file_obj: Dict[str, FilePolicy]):
        '''set SubjectNode's backing_files'''
        self.backing_files.update(file_obj)

    def get_obj_type(self) -> str:
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
    def __init__(self):
        super().__init__()
        self.uid: int = None
        self.gid: int = None
        self.sid: SELinuxContext = None
        self.cap: Capabilities = Capabilities()

    def get_node_name(self):
        return "file:%s" % (str(self.sid.type))

    def __repr__(self):
        return "<FileNode %s>" % self.sid.type

class IPCNode(GraphNode):
    def __init__(self, ipc_type: str):
        super().__init__()
        self.sid: SELinuxContext = None
        self.ipc_type = ipc_type

        # which subject owns this object (used for cred lookup)
        self.owner: SubjectNode = None

    # XXX 暂时这样
    # @property
    # def trusted(self):
    #     return self.owner.trusted

    # @trusted.setter
    # def trusted(self, v):
    #     raise ValueError("Cannot set IPC trust: set it on the owning subject")

    def get_node_name(self):
        return "%s:%s" % (self.ipc_type, self.sid.type)

    def __repr__(self):
        return "<IPCNode %s>" % self.sid.type

class SubjectNode(GraphNode):
    '''记录subject的父子关系'''
    def __init__(self, cred: Cred):
        super().__init__()
        self.parents : Set[SubjectNode] = set()
        self.children: Set[SubjectNode] = set()

        self.cred: Cred = cred
    
    @property
    def sid(self) -> SELinuxContext:
        return self.cred.sid
    
    @sid.setter
    def sid(self, v: SELinuxContext):
        self.cred.sid = v

    def get_node_name(self) -> str:
        return "subject:%s" % (self.sid.type)

class ProcessState(Enum):
    RUNNING = 1
    STOPPED = 2

class ProcessNode(GraphNode):
    def __init__(self, subject: SubjectNode, parent: Union[None, Self], exe: Dict[str, FilePolicy], pid: int, cred = Cred()):
        super().__init__()
        # process state
        self.state = ProcessState.STOPPED
        self.subject = subject
        self.parent = parent
        self.exe = exe
        self.pid = pid

        self.cred: Cred = cred
        self.children: Set[Self] = set()

    @property
    def sid(self):
        return self.cred.sid
    
    def __repr__(self):
        parent_type = self.parent.subject.sid.type if self.parent else "god"
        return "<ProcessNode %s->%s %s %s>" % (parent_type, self.subject.sid.type, list(self.exe.keys())[0], self.cred)

pass

