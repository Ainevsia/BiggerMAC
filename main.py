# sudo ./venv/bin/python main.py

import os
from extractor.androidsecuritypolicyextractor import AndroidSecurityPolicyExtractor
from extractor.zipextractor import ZipExtractor
from utils import check_root, set_working_directory, module_path
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
    ext.process_file()
    Logger.debug("Extractor done !")
    # now collect all selinux files from the file system !
    a = AndroidSecurityPolicyExtractor().walk_fs(os.path.join(ext.get_mnt(), 'splash2'))
    print(a)

    Logger.debug("main.py done")
    



