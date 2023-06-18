
import os
from typing import List

from utils import MODULE_PATH


class PolicyFiles:
    def __init__(self, name: str):
        self.base_name: str = os.path.join(MODULE_PATH, 'eval', name)
        self.policy_files: List[str] = []

    def __contains__(self, key: str) -> bool:
        return key in self.policy_files
    
    def __repr__(self) -> str:
        return f"PolicyFiles({self.base_name}, {self.policy_files})"

    def append(self, key: str):
        self.policy_files.append(key)

    