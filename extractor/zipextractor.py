from extractor.filesystemparser import AndroidSparseImageParser, LinuxExt4ImageParser
from utils.logger import Logger
from zipfile import ZipFile
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
        module_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        Logger.debug(f"ZipExtractor: module_path: {module_path}")
        zip_file_path_in = os.path.join(module_path, 'firmwares', self.filename)
        if not os.path.exists(zip_file_path_in):
            Logger.error(f"ZipExtractor: zip file not found: {zip_file_path_in}")
            return
        zip_file_path_out = os.path.join(module_path, 'firmwares_extracted', os.path.splitext(self.filename)[0])
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


    def process_file(self):
        '''process files in extracted_path'''
        import magic
        if not hasattr(self, 'extracted_path'):
            Logger.error("ZipExtractor: no extracted_path")
            return
        for dirpath, dirnames, filenames in os.walk(self.extracted_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                filetype = magic.from_file(filepath)
                if filetype.startswith('Android sparse image'):
                    Logger.debug(f"ZipExtractor: Android sparse image found: {filename}")
                    AndroidSparseImageParser(filepath).parse()
                elif filetype.startswith('Android bootimg'):
                    Logger.debug(f"ZipExtractor: Android bootimg found: {filename}")
                    exit(1)
                elif filetype.startswith('DOS/MBR boot sector'):
                    Logger.debug(f"ZipExtractor: DOS/MBR boot sector found: {filepath}")
                    LinuxExt4ImageParser(filepath).parse('vfat')
                elif filetype.startswith('Linux rev'):
                    Logger.debug(f"ZipExtractor: Linux rev found: {filename}")
                    LinuxExt4ImageParser(filepath).parse()
                else:
                    pass