
import os
from typing import List
from utils.logger import Logger
module_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def set_working_directory():
    '''Set a new directory as the current working directory'''
    Logger.debug(f"set_working_directory: {module_path}")
    os.chdir(module_path)

def check_root():
    if os.geteuid() != 0:
        Logger.error("check_root: Please run as root")
        raise PermissionError("check_root: Please run as root")

def split_path_all(path: str) -> List[str]:
    '''Split a path into all its components'''
    directories = []
    while True:
        path, directory = os.path.split(path)
        if directory != "":
            directories.insert(0, directory)
        else:
            break
    return directories