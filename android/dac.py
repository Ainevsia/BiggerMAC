from typing import Dict, List, Set
from android.capabilities import ALL_CAPABILITIES, Capabilities
from android.sepolicy import SELinuxContext
from utils import MODULE_PATH

class Cred():
    def __init__(self, uid = None, gid = None):
        self.uid = uid
        self.gid = gid
        self.groups: Set[int] = set()
        self.sid: SELinuxContext = None
        self.cap = Capabilities()

    def clear_groups(self):
        self.groups = set()

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __hash__(self):
        return hash(str(self))

    def execve(self, new_sid: SELinuxContext = None):
        '''return new SELinuxContext after execve of the current process'''
        import copy

        new = Cred(self.uid, self.gid)
        new.groups = copy.deepcopy(self.groups)

        if isinstance(new_sid, SELinuxContext):
            new.sid = copy.deepcopy(new_sid)
        else:
            new.sid = copy.deepcopy(self.sid)

        # TODO: check file if set-user-id and for file capabilities
        # TODO: handle capability(7) assignment semantics
        # TODO: file system capabilities /vendor/bin/pm-service

        # Drop by default, when transitioning to a non-privileged process
        if new.uid == 0:
            new.cap = copy.deepcopy(self.cap)

        return new

    def add_group(self, gid: str):
        if isinstance(gid, int):
            raise ValueError("Expected type str")
            # self.groups |= set([gid])
        elif isinstance(gid, str):
            self.groups |= set([AID_MAP_INV[gid]])
        else:
            raise ValueError("Expected type int or str")

    def add_groups(self, gids: List[str]):
        for gid in gids:
            self.add_group(self, gid)

    def __str__(self):
        additional_info = [
            "u=%s" % AID_MAP.get(self.uid, str(self.uid)),
            "g=%s" % AID_MAP.get(self.gid, str(self.gid)),
        ]

        if self.sid:
            additional_info += ["sid=" + str(self.sid)]
        if self.groups and len(self.groups):
            additional_info += ["groups=" + ",".join(map(lambda x: AID_MAP.get(x, str(x)), sorted(self.groups)))]

        if len(self.cap.effective):
            if len(self.cap.effective) == len(ALL_CAPABILITIES):
                additional_info += ["cap=EVERYTHING"]
            else:
                additional_info += ["cap=" + ",".join(list(self.cap.effective))]

        additional_info = " ".join(additional_info)

        return "<Cred %s>" % additional_info

def _parse_aid_file() -> Dict[int, str]:
    import re
    import os

    # Parse android AID definitions (/system/core/libcutils/include_vndk/cutils/android_filesystem_config.h)

    # TODO: this is not completely cross-vendor as some vendors fork this file and add custom UIDs to it
    # The solution to this that is to extract the exported table symbol `android_id` from the libc.so ELF
    # or to invoke getpwuid() on real box to retrieve the tuple.
    try:
        with open(os.path.join(MODULE_PATH, 'externals', 'android_fs.h'), 'r') as fp:
            data = fp.read()
    except IOError:
        raise IOError("Unable to find android_fs.h file (uid/gid mapping)")

    mapping: Dict[int, str] = {}
    got_range = False
    range_start = 0

    for line in data.split("\n"):
        if re.match(r'^\s*((/\*)|(//)|($))', line): continue # Ignore comments and blank lines

        tokens = list(filter(lambda x: x != "", line.split(" ")))
        aid_name = tokens[1]
        aid: int = int(tokens[2])

        assert aid_name[:4] == "AID_"

        if got_range:
            assert aid_name.endswith("_END")
            got_range = False
            aid_name = aid_name[4:-4].lower()

            # exceptions to the rules
            if aid_name.startswith("oem"):
                aid_name = "oem"

            for i in range(range_start, aid+1):
                mapping[i] = "%s_%d" % (aid_name, i)
            continue

        if aid_name.endswith("_START"):
            got_range = True
            range_start = aid
            continue

        # XXX: there are some exceptions to this (mediacodec, etc.)
        aid_name = aid_name[4:].lower()

        # Some exceptions to the rule
        if aid_name in ['media_codec', 'media_ex', 'media_drm']:
            aid_name = aid_name.replace('_', '')

        # XXX: not handling ranges
        mapping[aid] = aid_name

    return mapping

# number to name
# https://blog.csdn.net/lewif/article/details/49801359
AID_MAP: Dict[int, str] = _parse_aid_file()
AID_MAP_INV: Dict[str, int] = dict([[v,k] for k,v in AID_MAP.items()])
