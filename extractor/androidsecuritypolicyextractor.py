import os
from fs.filesystempolicy import FilePolicy, FileSystemPolicy


class AndroidSecurityPolicyExtractor():
    def __init__(self):
        pass

    def walk_fs(self, toplevel_path: str) -> FileSystemPolicy:
        fsp = FileSystemPolicy()
        toplevel_components = toplevel_path.split(os.sep)
        for root, dirs, files in os.walk(toplevel_path, followlinks=False):
            for obj in dirs + files:
                path = os.path.normpath(os.path.join(root, obj))
                path_components = path.split(os.sep)
                # translate the path to absolute relative to the filesystem image base directory
                fs_relative_path = os.path.join("/", *path_components[len(toplevel_components):])
                file_policy = FilePolicy(path)
                # store the file metadata in the policy
                fsp.add_file(fs_relative_path, file_policy)
        return fsp

