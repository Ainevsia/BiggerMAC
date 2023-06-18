
import re
from typing import Dict

PROPERTY_KEY = re.compile(r'[-_.a-zA-Z0-9]+')   # 匹配-_.等的key字符串
PROPERTY_VALUE = re.compile(r'[^#]*')
PROPERTY_KV = re.compile(r'^\s*([-_.a-zA-Z0-9]+)\s*=\s*([^#]*)')

class AndroidPropertyList:
    '''all properties in the Android system, only one field: prop'''
    def __init__(self):
        self.prop: Dict[str, str] = {}

    def __getitem__(self, key: str) -> str:
        return self.prop[key]
    
    def __setitem__(self, key: str, value: str):
        self.prop[key] = value

    def __contains__(self, key: str) -> bool:
        return key in self.prop

    def __repr__(self):
        res = object.__repr__(self) + '\n'
        for attribute, value in self.__dict__.items():
            res += attribute +  " = " + str(value) + '\n'
        return res
    
    def _merge(self, other: Dict[str, str]):
        for k, v in other.items():
            self.prop[k] = v

    def from_file(self, filename: str):
        '''从file中读取出配置文件，合并入当前类（覆盖）'''
        prop_raw_data = open(filename, 'r').read()
        properties = {}

        for line in prop_raw_data.split("\n"):
            # Ignore comments and blank lines
            if re.match(r'^(\s*#)|(\s*$)', line): continue
            # Ignore import statements
            if re.match('^import', line): continue
            # Match property assignments (right side can be blank)
            result = PROPERTY_KV.match(line)
            if result is None: continue

            prop, value = result.groups()
            properties[prop] = value

        # Merge in the final found properties
        self._merge(properties)

    def to_file(self, filename: str):
        '''文本形式写入file中'''
        with open(filename, 'w') as fp:
            for k, v in self.prop.items():
                fp.write("%s=%s\n" % (k, v))

    def get_default(self, key: str, default: str = ""):
        if key not in self.prop: return default
        else: return self.prop[key]

    def get_multi_default(self, keys: str, default: str = ""):
        """ Try multiple keys returning the first found or the default """
        for key in keys:
            if key in self.prop:
                return self.prop[key]

        return default
