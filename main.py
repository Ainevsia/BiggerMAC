# sudo ./venv/bin/python main.py

import os
from typing import List
from android.init import AndroidInit
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from extractor.androidsecuritypolicyextractor import AndroidSecurityPolicyExtractor
from extractor.zipextractor import ZipExtractor
from fs.filecontext import read_file_contexts
from fs.filesystempolicy import FileSystem
from utils import check_root, set_working_directory, MODULE_PATH
from utils.logger import Logger
import argparse

if __name__ == "__main__":
    check_root()
    set_working_directory()
    Logger.debug("main.py")
    parser = argparse.ArgumentParser()
    # parser.add_argument("--policy_name")
    args = parser.parse_args()
    # ext = ZipExtractor('Huawei_Mate_50_Pro_DCO-LX9_103.0.0.126_C10E10R2P1_Product_Combination_Software_EMUI13.0.0_05019ASD_Dload.zip')
    ext = ZipExtractor('Huawei_Mate_20.zip')
    ext.split_update_app() 
    fs_lst: List[FileSystem] = ext.process_file()
    Logger.debug(f"fs_lst: {fs_lst}")
    Logger.debug("Extractor done !")
    # now collect all selinux files from the file system
    asp: AndroidSecurityPolicy = AndroidSecurityPolicyExtractor(fs_lst, 'Huawei_Mate_20').extract_from_firmware()
    major, minor, revision = asp.get_android_version()
    if major >= 9:
        file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
        file_contexts += read_file_contexts(asp.get_saved_file_path("vendor_file_contexts"))
    init = AndroidInit(asp)
    hw = init.determine_hardware()
    Logger.debug(f"hw: {hw}")
    init.read_configs("/init.rc")


    
    Logger.debug("main.py done")

def main_process():
    '''开始进行对策略文件的分析'''
    init = AndroidInit()






