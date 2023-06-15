import os, stat

from android.sepolicy import SELinuxContext
from utils.logger import Logger

class FilePolicy:
    def __init__(self, path: str):
        # get the information of the symbolic link itself, not its target
        st = os.lstat(path)

        # Collect DAC policy
        perms = st[stat.ST_MODE]
        user = st[stat.ST_UID]
        group = st[stat.ST_GID]
        size = st[stat.ST_SIZE]
    
        self.original_path = path   # filepath in the host's filesystem
        self.user = user
        self.group = group
        self.perms = perms
        self.size = size
        self.link_path = os.readlink(path) if stat.S_ISLNK(perms) else ''
        self.selinux = None
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
    
class FileSystemPolicy: 
    def __init__(self):
        self.files: dict(str, FilePolicy) = {}

    def __repr__(self):
        res = object.__repr__(self) + '\n'
        for attribute, value in self.__dict__.items():
            res += attribute +  " = " + str(value) + '\n'
        return res

    def add_file(self, path: str, file_policy: FilePolicy):
        if path != "/" and path.endswith("/"):
            raise ValueError("Paths must be cannonicalized! %s" % path)
        if path in self.files:
            raise ValueError("Cannot re-add existing path '%s' to policy" % path)
        self.files[path] = file_policy