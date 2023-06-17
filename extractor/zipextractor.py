from typing import List
from extractor.filesystemparser import AndroidSparseImageParser, LinuxExt4ImageParser, AndroidBootingParser
from fs.filesystempolicy import FileSystem
from utils.logger import Logger
from zipfile import ZipFile
from utils import MODULE_PATH
import os

class ZipExtractor:
    '''extract zipped firmware'''
    def __init__(self, filename: str) -> 'ZipExtractor':
        self.filename = os.path.basename(filename)
        Logger.info(f"ZipExtractor init: {self.filename}")
        self.extract()
        
    def extract(self):
        '''extract zipped firmware once (may have recursive zipped files)'''
        Logger.info("ZipExtractor status: start")
        if not hasattr(self, 'filename'):
            Logger.error("ZipExtractor: no filename")
            return
        Logger.debug(f"ZipExtractor: module_path: {MODULE_PATH}")
        zip_file_path_in = os.path.join(MODULE_PATH, 'firmwares', self.filename)
        if not os.path.exists(zip_file_path_in):
            Logger.error(f"ZipExtractor: zip file not found: {zip_file_path_in}")
            return
        zip_file_path_out = os.path.join(MODULE_PATH, 'firmwares_extracted', os.path.splitext(self.filename)[0])
        Logger.debug(f"ZipExtractor: zip_file_path_out: {zip_file_path_out}")
        self.extracted_path = zip_file_path_out
        if not os.path.exists(zip_file_path_out):
            os.makedirs(zip_file_path_out)
            with ZipFile(zip_file_path_in, 'r') as zf:
                zf.extractall(zip_file_path_out)
            Logger.info(f"ZipExtractor: zip file extracted: {zip_file_path_out}")
        else:
            Logger.warning(f"ZipExtractor: zip file already extracted: {zip_file_path_out}")
        
        # 使用 os.walk() 遍历文件系统
        for dirpath, dirnames, filenames in os.walk(zip_file_path_out):
            # dirpath: 当前目录路径
            # dirnames: 当前目录下的子目录名列表
            # filenames: 当前目录下的文件名列表
            for filename in filenames:
                if filename.endswith('.zip'):
                    Logger.debug(f"ZipExtractor: recursive zipped file found: {filename}")
                    zip_file_path_in = os.path.join(dirpath, filename)
                    zip_file_path_out = os.path.join(dirpath, os.path.splitext(filename)[0])
                    if not os.path.exists(zip_file_path_out):
                        os.makedirs(zip_file_path_out)
                        with ZipFile(zip_file_path_in, 'r') as zf:
                            zf.extractall(zip_file_path_out)
                        Logger.info(f"ZipExtractor: recursive zipped file extracted: {zip_file_path_out}")
                    else:
                        Logger.warning(f"ZipExtractor: recursive zipped file already extracted: {zip_file_path_out}")
            
        Logger.info("ZipExtractor status: done")
        return

    def split_update_app(self):
        '''use python script splituapp.py(an external tool) to split update.app'''
        from utils.splituapp import extract
        if not hasattr(self, 'extracted_path'):
            Logger.error("ZipExtractor: no extracted_path")
            return
        for dirpath, dirnames, filenames in os.walk(self.extracted_path):
            for filename in filenames:
                if filename.lower() == 'update.app':
                    extract(os.path.join(dirpath, filename))

    def process_file(self) -> List[FileSystem]:
        '''process files in extracted_path, return file system'''
        import magic
        if not hasattr(self, 'extracted_path'):
            Logger.error("ZipExtractor: no extracted_path")
            return
        fs_lst: List[FileSystem] = []
        for dirpath, dirnames, filenames in os.walk(self.extracted_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                filetype = magic.from_file(filepath)
                fs = None
                if filetype.startswith('Android sparse image'):
                    Logger.debug(f"ZipExtractor: Android sparse image found: {filename}")
                    fs = AndroidSparseImageParser(filepath).parse()
                elif filetype.startswith('Android bootimg'):
                    Logger.debug(f"ZipExtractor: Android bootimg found: {filename}")
                    fs = AndroidBootingParser(filepath).parse()
                elif filetype.startswith('DOS/MBR boot sector'):
                    Logger.debug(f"ZipExtractor: DOS/MBR boot sector found: {filepath}")
                    fs = LinuxExt4ImageParser(filepath).parse('vfat')
                elif filetype.startswith('Linux rev'):
                    Logger.debug(f"ZipExtractor: Linux rev found: {filename}")
                    fs = LinuxExt4ImageParser(filepath).parse()
                else:
                    pass
                if isinstance(fs, FileSystem):
                    # print('+++' + filepath)
                    fs_lst.append(fs)
        return fs_lst
    
    def get_mnt(self):
        '''get mount point of extracted file'''
        return os.path.join(MODULE_PATH, 'firmwares_mnt', os.path.splitext(self.filename)[0])