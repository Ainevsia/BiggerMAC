import shutil
from fs.filesystempolicy import FileSystem
from utils import MODULE_PATH, split_path_all
from utils.logger import Logger
from utils.shellcommand import ShellCommandExecutor
import os
import subprocess

class FilesystemParser:
    def __init__(self, path: str):
        self.filepath = path
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"FilesystemParser: file not found: {self.filepath}")
        
        # extract the mount point name from the path
        path_lst = split_path_all(self.filepath)
        while len(path_lst) >= 2 and path_lst[-2] != 'firmwares_extracted':
            path_lst.pop()
        if len(path_lst) < 2 or path_lst[-2] != 'firmwares_extracted':
            raise FileNotFoundError(f"FilesystemParser: firmwares_extracted not found: {self.filepath}")
        self.firmware_name = path_lst[-1]
        Logger.info(f"FilesystemParser: firmware_name: {self.firmware_name}")
        self.mount_point = os.path.join(MODULE_PATH, 'firmwares_mnt', self.firmware_name)
        if not os.path.exists(self.mount_point):
            os.makedirs(self.mount_point)
        self.booting_extraced =  os.path.join(MODULE_PATH, 'firmwares_booting_extracted', self.firmware_name)
        if not os.path.exists(self.booting_extraced):
            os.makedirs(self.booting_extraced)
        self.filename = os.path.splitext(os.path.basename(self.filepath))[0]

class AndroidSparseImageParser(FilesystemParser):
    def __init__(self, path: str):
        super().__init__(path)
    
    def parse(self) -> FileSystem:
        '''use simg2img to convert sparse image to raw image'''
        simg2img = os.path.join(MODULE_PATH, 'externals', 'android-simg2img', 'simg2img')
        if not os.path.exists(simg2img):
            raise FileNotFoundError(f"AndroidSparseImageParser: simg2img not found: {simg2img}")
        ext4_file_path = os.path.splitext(self.filepath)[0] + '.ext4'
        if not os.path.exists(ext4_file_path):
            ShellCommandExecutor([simg2img, self.filepath, ext4_file_path]).execute()        
            Logger.info(f"AndroidSparseImageParser: sparse image converted: {ext4_file_path}")
        import magic
        filetype = magic.from_file(ext4_file_path)
        if filetype.startswith('F2FS filesystem'):
            Logger.info(f"AndroidSparseImageParser: F2FS filesystem: {ext4_file_path}")
            # cannot process this now ...
            return
        elif filetype.startswith('Linux rev'):
            Logger.info(f"AndroidSparseImageParser: Linux rev: {ext4_file_path}")
            return LinuxExt4ImageParser(ext4_file_path).parse()
        else:
            Logger.error(f"AndroidSparseImageParser: unknown filetype: {ext4_file_path} --> {filetype}")
            pass

class LinuxExt4ImageParser(FilesystemParser):   # make sure the image is ext4
    def __init__(self, path: str):
        super().__init__(path)
    
    def parse(self, fs_type: str = 'ext4') -> FileSystem:
        '''use mount to mount ext4 image'''
        mount_dir = os.path.join(self.mount_point, os.path.splitext(os.path.basename(self.filepath))[0])
        if not os.path.exists(mount_dir):
            os.makedirs(mount_dir)
        process1 = subprocess.Popen(["mount"], stdout=subprocess.PIPE)
        process2 = subprocess.Popen(["grep", mount_dir], stdin=process1.stdout, stdout=subprocess.PIPE)
        process2.communicate()
        if process2.returncode != 0:    # not mounted
            res = ShellCommandExecutor(['mount', '-o', 'ro', '-t', fs_type, self.filepath, mount_dir]).execute()
            if res != 0:
                Logger.error(f"LinuxExt4ImageParser: mount failed: {self.filepath}")
                return
            else:
                Logger.info(f"LinuxExt4ImageParser: mount success: {self.filepath}")
        return FileSystem(mount_dir, self.filename)

class AndroidBootingParser(FilesystemParser):
    def __init__(self, path: str):
        super().__init__(path)

    def parse(self) -> FileSystem:
        '''use imgtool'''
        imjtool = os.path.join(MODULE_PATH, 'externals', 'imjtool', 'imjtool.ELF64')
        if not os.path.exists(imjtool):
            raise FileNotFoundError(f"AndroidBootingParse: imjtool not found: {imjtool}")
        lz4 = os.path.join(MODULE_PATH, 'externals', 'lz4', 'lz4')
        if not os.path.exists(lz4):
            raise FileNotFoundError(f"AndroidBootingParse: lz4 not found: {lz4}")
        os.chdir(self.booting_extraced)
        if not os.path.exists(os.path.join(self.booting_extraced, f'{self.filename}-extracted')):
            ShellCommandExecutor([imjtool, self.filepath, 'extract']).execute()
            os.rename(os.path.join(self.booting_extraced, 'extracted'), os.path.join(self.booting_extraced, f'{self.filename}-extracted'))
        os.chdir(MODULE_PATH)
        ramdisk_file_path = os.path.join(self.booting_extraced, f'{self.filename}-extracted', 'ramdisk')
        ramdisk_out_path = os.path.join(self.booting_extraced, f'{self.filename}-ramdisk.cpio')
        import magic
        filetype = magic.from_file(ramdisk_file_path)
        if filetype.startswith('LZ4'):
            if not os.path.exists(ramdisk_out_path):
                os.makedirs(ramdisk_out_path)
                process1 = subprocess.Popen([lz4, '-dc', ramdisk_file_path], stdout=subprocess.PIPE)
                process2 = subprocess.Popen(['cpio', '-idm', '-D', ramdisk_out_path], stdin=process1.stdout, stdout=subprocess.PIPE)
                process2.communicate()
        elif filetype.startswith('gzip'):
            if not os.path.exists(ramdisk_out_path):
                os.makedirs(ramdisk_out_path)
                process1 = subprocess.Popen(['gunzip', '-c', ramdisk_file_path], stdout=subprocess.PIPE)
                process2 = subprocess.Popen(['cpio', '-idm', '-D', ramdisk_out_path], stdin=process1.stdout, stdout=subprocess.PIPE)
                process2.communicate()
        else:
            print(filetype)
            Logger.error(f"AndroidBootingParse: unknown filetype: {ramdisk_file_path} --> {filetype}")
            exit(1)
        shutil.rmtree(os.path.join(self.booting_extraced, f'{self.filename}-extracted'))
        return FileSystem(ramdisk_out_path, self.filename)