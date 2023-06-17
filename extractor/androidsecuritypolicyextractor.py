import copy
import fnmatch
import os
import pickle
import shutil
from typing import Dict, List
from android.property import AndroidPropertyList
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from fs.filesystempolicy import FilePolicy, FileSystem, FileSystemPolicy
from utils.logger import Logger
from utils import MODULE_PATH

TARGET_FILESYSTEMS = [
    {
        "name": "boot",
        "pattern": "*ramdisk*", 
    },
    {
        "name": "system",
        "pattern": "*system*",
    },
    {
        "name": "vendor",
        "pattern": "*vendor*",
    },
    {
        "name": "odm",
        "pattern": "*odm*",
    },
]

SEPOLICY_FILES = [
    'sepolicy',
    'precompiled_sepolicy', # Treble devices (if it has been compiled)
    'selinux_version', # may or may not be there
    'genfs_contexts', # not sure if this exists - found in binary sepolicy

    # file
    'file_contexts',
    'file_contexts.bin', # found in newer Android versions (>7.0)
    'plat_file_contexts',
    'nonplat_file_contexts',
    'vendor_file_contexts',

    # seapp
    'seapp_contexts',
    'plat_seapp_contexts',
    'nonplat_seapp_contexts',
    'vendor_seapp_contexts',

    # property
    'property_contexts',
    'plat_property_contexts',
    'nonplat_property_contexts',
    'vendor_property_contexts',

    # service
    'service_contexts',
    'plat_service_contexts',
    'nonplat_service_contexts',
    'vndservice_contexts',

    # hwservice
    'hwservice_contexts',
    'plat_hwservice_contexts',
    'nonplat_hwservice_contexts',
    'vendor_hwservice_contexts',

    # TODO: also get fs_config_files and fs_config_dirs

    # Middleware MAC
    'mac_permissions.xml', # TODO: Treble has /vendor and /system versions of this
    'ifw.xml',
    'eops.xml'
]


class AndroidSecurityPolicyExtractor():
    def __init__(self, fs_lst: List[FileSystem], name: str):
        self.fs_lst = fs_lst
        self.name = name
        self.combined_fs: FileSystemPolicy = None
        self.properties: AndroidPropertyList = None

    def walk_fs(self, toplevel_path: str) -> FileSystemPolicy:
        fsp = FileSystemPolicy()
        toplevel_components = toplevel_path.split(os.sep)
        for root, dirs, files in os.walk(toplevel_path, onerror=lambda: exit(1), followlinks=False):
            for obj in dirs + files:
                path = os.path.normpath(os.path.join(root, obj))
                path_components = path.split(os.sep)
                # translate the path to absolute relative to the filesystem image base directory
                fs_relative_path = os.path.join("/", *path_components[len(toplevel_components):])
                file_policy = FilePolicy(path)
                # store the file metadata in the policy
                fsp.add_file(fs_relative_path, file_policy)
        return fsp
    
    def extract_from_firmware(self) -> AndroidSecurityPolicy:
        fs_policies: Dict[str, FileSystemPolicy] = {}
        for fs in TARGET_FILESYSTEMS:
            # TODO: there maybe multiple filesystems that match the pattern
            # eg. erecovery_vendor recovery_vendor vendor are all `vendor` pattern
            match = set(filter(lambda x: fnmatch.fnmatch(x.name, fs["pattern"]), self.fs_lst))
            for _fs in match:
                fs_policies[_fs.name] = self.walk_fs(_fs.path)
        
        # Determine how the firmware is organized
        #    a. Boot is loaded and a system partition is mounted
        #    b. Boot loads initially and then transitions to /system as the rootfs

        # corresponds to system

        sepolicy_in_system = fs_policies["system"].find('/sepolicy')
        treble_enabled = fs_policies["system"].find("/system/etc/selinux/plat_sepolicy.cil")
        
        # Image configurations 系统如何启动起来
        #  1. Legacy two stage boot
        #  2. Single stage boot
        #  3. Single stage boot (treble)

        if sepolicy_in_system or treble_enabled:
            combined_fs: FileSystemPolicy = copy.deepcopy(fs_policies["system"])
            combined_fs.add_mount_point("/", "rootfs", "rootfs", ["rw"])
            combined_fs.add_mount_point("/system", "ext4", "/dev/block/bootdevice/by-name/system", ["rw"])
        
        Logger.info(f'Found system partition {len(combined_fs.files)}')
        if "vendor" in fs_policies:
            combined_fs.mount(fs_policies['vendor'], "/vendor")
            Logger.info(f'Found vendor partition {len(combined_fs.files)}')
        if "odm" in fs_policies:
            combined_fs.mount(fs_policies['odm'], "/odm")
            Logger.info(f'Found odm partition {len(combined_fs.files)}')
        
        # Extract out the policy files (from most preferential to least)
        for fn, fp in combined_fs.files.items():
            filebase = os.path.basename(fn)
            # extract out sepolicy related files 所有的策略定义文件
            if filebase in SEPOLICY_FILES:
                file_name = os.path.basename(fp.original_path)
                self.save_file(fp.original_path, file_name)

                Logger.info(f'Found sepolicy file {file_name}')

        self.combined_fs = combined_fs
        self.extract_properties()
        self.extract_init()

        self.save()

        return AndroidSecurityPolicy(self.combined_fs, self.properties, self.name, fs_policies)

    def save_file(self, source: str, path: str, overwrite: bool = False):
        '''将文件从挂载点保存至eval汇总目录中'''
        save_path = os.path.join(MODULE_PATH, 'eval', self.name, path)
        if not os.path.exists(os.path.dirname(save_path)):
            os.makedirs(os.path.dirname(save_path))
        if not os.path.exists(source):
            Logger.error(f'File {source} does not exist')
            return
        if not os.path.isfile(source):
            Logger.error(f'File {source} is not a file')
            return
        if not overwrite and os.path.exists(save_path):
            Logger.warning(f'File {save_path} already exists')
            return
        Logger.info(f'Saving file {save_path}')
        shutil.copyfile(source, save_path)

    def extract_properties(self):
        # 保存所有的属性文件
        prop_files: List[str] = []

        # Extract out prop files
        prop_files += self.combined_fs.find('*.prop')
        prop_files += self.combined_fs.find("prop.default")

        props = AndroidPropertyList()
        
        # TODO: ensure ordering of property files!
        # Ref: https://rxwen.blogspot.com/2010/01/android-property-system.html
        for prop_file in prop_files:
            src = self.combined_fs.files[prop_file].original_path
            props.from_file(src)
            self.save_file(src, os.path.join("prop", prop_file[1:]))

        if 'ro.build.version.release' not in props.prop:
            raise Exception("Invalid firmware image '%s': missing Android version in props files" % self.asp.firmware_name)

        self.properties = props

    def extract_init(self):
        rc_files = []

        # Extract out prop files
        rc_files = self.combined_fs.find("*.rc")

        for rc_file in rc_files:
            src = self.combined_fs.files[rc_file].original_path
            self.save_file(src, os.path.join("init", rc_file[1:]))

        fstab_files = self.combined_fs.find("*fstab*")
        for fstab_file in fstab_files:
            src = self.combined_fs.files[fstab_file].original_path
            self.save_file(src, os.path.join("init", fstab_file[1:]))

    def save(self):
        self.properties.to_file(os.path.join(MODULE_PATH, 'eval', self.name, 'all_properties.prop'))
        Logger.info(f'Saved all properties')
        self.save_db(self.combined_fs, "combined_fs.pkl")

    def save_db(self, obj: object, name: str):
        db_dir = os.path.join(MODULE_PATH, 'eval', self.name, "db")
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        if not os.access(db_dir, os.W_OK):
            raise ValueError("Unable to open '%s' database for writing" % name)
        with open(os.path.join(db_dir, name), 'wb') as fp:
            pickle.dump(obj, fp, protocol=pickle.DEFAULT_PROTOCOL)
        Logger.info(f'Saved database {name}')

    def load(self):
        self.properties = AndroidPropertyList()
        self.properties.from_file(os.path.join(MODULE_PATH, 'eval', self.name, 'all_properties.prop'))
        self.combined_fs = self.load_db("combined_fs.pkl")
