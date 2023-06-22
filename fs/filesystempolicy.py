import fnmatch
import os, stat
from typing import Dict, List, Self

from android.sepolicy import SELinuxContext
from utils.logger import Logger

class FilePolicy:
    def __init__(self, path: str):
        # get the information of the symbolic link itself, not its target
        st = os.lstat(path)

        # Collect DAC policy
        perms: int = st[stat.ST_MODE]
        user: int = st[stat.ST_UID]
        group: int = st[stat.ST_GID]
        size: int = st[stat.ST_SIZE]
    
        self.original_path = path   # filepath in the host's filesystem
        self.user = user
        self.group = group
        self.perms = perms
        self.size = size
        self.link_path = os.readlink(path) if stat.S_ISLNK(perms) else ''
        self.selinux: SELinuxContext = None
        self.capabilities: int = None

        # Collect MAC (SELinux) and other security policies (capabilities)
        xattrs = {}

        # Get all extended attributes
        for xattr in os.listxattr(path, follow_symlinks=False):
            # These are binary data (SELinux is a C-string, Capabilies is a 64-bit integer)
            xattrs.update({xattr: os.getxattr(path, xattr, follow_symlinks=False)})
        for k, v in xattrs.items():
            if k == "security.selinux":
                # strip any opening/closing quotes
                sel = v.strip(b"\x00").decode('ascii')
                self.selinux = SELinuxContext.FromString(sel)
            elif k == "security.capability":
                # capabilities can vary in size depending on the version
                # see ./include/uapi/linux/capability.h in the kernel source tree for more information
                cap = int.from_bytes(v, byteorder='little')
                self.capabilities = cap
            else:
                Logger.warn("Unparsed extended attribute key %s", k)

    def __repr__(self):
        return self.original_path

    @staticmethod
    # 创建一个原系统中不存在的伪文件
    def create_pseudo_file(user: int, group: int, perm: int) -> Self:
        fp = FilePolicy.__new__(FilePolicy)
        fp.original_path = None
        fp.user = user
        fp.group = group
        fp.perms = perm
        fp.size = 4096
        fp.link_path = ""
        fp.capabilities = None
        fp.selinux = None
        return fp

class MountPoint:
    def __init__(self, type: str, device: str, options: List[str]):
        self.type = type
        self.device = device
        self.options = options

class FileSystem:
    def __init__(self, path: str, name: str):
        self.name = name
        self.path = path

    def __repr__(self):
        return f'<FileSystem {self.name} -> {self.path}>'
    
    def __eq__(self, __value: object) -> bool:
        if isinstance(__value, FileSystem):
            return self.name == __value.name and self.path == __value.path
        return False
    
    def __hash__(self) -> int:
        return hash((self.name, self.path))

class FileSystemPolicy: 
    def __init__(self):
        self.files: Dict[str, FilePolicy] = {}
        self.mount_points: Dict[str, MountPoint] = {}

    def __repr__(self):
        # only display the first x elements of self.files
        # this is because the filesystems can have thousands of files
        # and printing all of them is not helpful
        return f"<FileSystemPolicy {dict(list(self.files.items())[:1])}>"

    def __getitem__(self, key: str) -> str:
        '''Get the original path of a file in the policy'''
        if key not in self.files:
            raise KeyError("File %s not in policy" % key)
        return self.files[key].original_path

    def __contains__(self, key: str) -> bool:
        return key in self.files

    def add_file(self, path: str, file_policy: FilePolicy):
        if path != "/" and path.endswith("/"):
            raise ValueError("Paths must be cannonicalized! %s" % path)
        if path in self.files:
            raise ValueError("Cannot re-add existing path '%s' to policy" % path)
        self.files[path] = file_policy
    
    def find(self, pattern: str) -> List[str]:
        '''Find all files that match the given pattern'''
        return list(filter(lambda x: fnmatch.fnmatch(x, pattern), self.files.keys()))
    
    def add_mount_point(self, path: str, fstype: str, device: str, options: List[str]):
        path = os.path.normpath(path)
        if path in self.mount_points:
            raise ValueError("Cannot readd mount-point %s without remount" % (path))
        self.mount_points[path] = MountPoint(fstype, device, options)

    def mount(self, other_fs: Self, mount_point: str):
        '''Mount a filesystem into the policy'''
        # transform all paths
        for fn, v in other_fs.files.items():
            # ensure all paths are absolute
            assert fn[0] == "/"
            # remove leading slash, making fn relative
            fn = fn[1:]
            # special case: root of other_fs is now mount point
            if fn == "":
                self.files[mount_point] = v
                continue
            self.add_file(os.path.join(mount_point, fn), v)
    
    def mkdir(self, path: str, user: int = 0, group: int = 0, perm: int = 0o755):
        fp: FilePolicy = FilePolicy.create_pseudo_file(user, group, (perm & 0o7777) | stat.S_IFDIR)
        self.add_or_update_file(path, fp)
        
    def add_or_update_file(self, path, policy_info: FilePolicy):
        if path != "/" and path.endswith("/"): raise ValueError("Paths must be cannonicalized! %s" % path)
        self.files[path] = policy_info

    def chown(self, path: str, user: int, group: int):
        if path not in self.files: raise KeyError("File %s not in policy" % path)
        self.files[path].user = user
        self.files[path].group = group

    def chmod(self, path: str, perm: int):
        '''Change the permission of a file'''
        if path not in self.files: return
        fp: FilePolicy = self.files[path]
        fp.perms = (fp.perms & ~0o7777) | (perm & 0o7777)
