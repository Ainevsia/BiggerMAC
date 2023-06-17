from android.property import AndroidPropertyList
from extractor.androidsecuritypolicy import AndroidSecurityPolicy
from fs.filesystempolicy import FileSystemPolicy
from utils.logger import Logger


class AndroidInit():
    def __init__(self, asp: AndroidSecurityPolicy):
        self.asp = asp
    
    def determine_hardware(self) -> str:
        rohw = 'ro.hardware'
        if rohw not in self.asp.properties:
            import re
            for pattern, regex in [
                ("*uevent*rc", r'.*ueventd\.([-_a-zA-Z0-9]+)\.rc'),
                ("*fstab.*",   r'.*fstab\.([-_a-zA-Z0-9]+)'),]:

                results = self.asp.fs_policies['system'].find(pattern)
                for result in results:
                    match = re.match(regex, result)

                    if match:
                        ro_hardware_guess = match.group(1)
                        self.asp.properties[rohw] = ro_hardware_guess
                        print("[!] " + ro_hardware_guess)
                        break
        if ro_hardware_guess:
            Logger.info(f"Guessing ro.hardware as {ro_hardware_guess}")
            self.asp.properties[rohw] = ro_hardware_guess
        return self.asp.properties[rohw]