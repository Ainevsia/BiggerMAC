import subprocess
from typing import List, Tuple

from utils.logger import Logger

class ShellCommandExecutor():
    def __init__(self, cmdlst: List[str]):
        self.cmdlst = cmdlst
    
    def execute(self) -> Tuple[str, str]:
        Logger.debug(f"ShellCommandExecutor: cmdlst: {self.cmdlst}")
        proc = subprocess.Popen(self.cmdlst, 
                                shell=False, 
                                encoding='utf-8',
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        stdout_data, stderr_data = proc.communicate()
        Logger.debug(f"ShellCommandExecutor: stdout_data: {stdout_data}")
        return stdout_data, stderr_data