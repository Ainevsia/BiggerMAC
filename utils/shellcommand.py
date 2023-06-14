import subprocess
from typing import List, Tuple

from utils.logger import Logger

class ShellCommandExecutor():
    def __init__(self, cmdlst: List[str]):
        self.cmdlst = cmdlst
    
    def execute(self) -> int:
        Logger.debug(f"ShellCommandExecutor: cmdlst: {self.cmdlst}")
        proc = subprocess.Popen(self.cmdlst, 
                                shell=False, 
                                encoding='utf-8',
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE)
        # stdout_data, stderr_data = proc.communicate()
        proc.communicate()
        # Logger.debug(f"ShellCommandExecutor: stdout_data: {stdout_data}")
        return proc.returncode  # success: 0, error: 1