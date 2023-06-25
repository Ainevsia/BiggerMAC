# sudo ./venv/bin/python main.py

import os
from typing import List
from android.init import AndroidInit
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from extractor.androidsecuritypolicyextractor import AndroidSecurityPolicyExtractor
from extractor.zipextractor import ZipExtractor
from fs.filecontext import read_file_contexts
from fs.filesysteminstance import FileSystemInstance
from fs.filesystempolicy import FileSystem
from se.sepolicygraph import PolicyGraph, SELinuxPolicyGraph
from utils import check_root, set_working_directory, MODULE_PATH
from utils.logger import Logger
import argparse

if __name__ == "__main__":
    check_root()
    set_working_directory()

    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    
    name = 'Huawei_Mate_20'
    ext = ZipExtractor(f'{name}.zip')
    ext.split_update_app() 
    fs_lst: List[FileSystem] = ext.process_file()
    Logger.debug("Extractor done !")
    
    asp: AndroidSecurityPolicy = AndroidSecurityPolicyExtractor(fs_lst, name).extract_from_firmware()
    major, minor, revision = asp.get_android_version()
    assert major >= 9, "Only Android 9+ is supported"
    file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
    file_contexts += read_file_contexts(asp.get_saved_file_path("vendor_file_contexts"))
    init = AndroidInit(asp)
    init.determine_hardware()
    init.read_configs()
    init.boot_system()

    ################################
    # Parse SEPolicy file
    ################################
    print(asp.policy_files)
    sepolicy = None
    if "sepolicy" in asp.policy_files:
        sepolicy = asp.get_saved_file_path("sepolicy")
    elif "precompiled_sepolicy" in asp.policy_files:
        sepolicy = asp.get_saved_file_path("precompiled_sepolicy")
    if not sepolicy: raise Exception("No sepolicy file found")
    graph = SELinuxPolicyGraph(sepolicy)
    pg: PolicyGraph = graph.build_graph()
    Logger.debug("Overlaying policy to filesystems")


    ################################
    # Simulate the whole system
    ################################
    res = FileSystemInstance(pg, init, file_contexts).instantiate()
    Logger.debug("main.py done")





