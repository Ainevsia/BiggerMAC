import re
from stat import S_IFCHR, S_IFIFO, S_IFDIR, S_IFBLK, S_IFREG, S_IFLNK, S_IFSOCK
from typing import Dict, List
from android.sepolicy import SELinuxContext

from utils.logger import Logger

F_MODE = {S_IFIFO: '-p',
          S_IFCHR: '-c',
          S_IFDIR: '-d',
          S_IFBLK: '-b',
          S_IFREG: '--',
          S_IFLNK: '-l',
          S_IFSOCK: '-s'}

'''
  -b - Block Device
◦ -c - Character Device
◦ -d - Directory
◦ -p - Named Pipe (FIFO)
◦ -l - Symbolic Link
◦ -s - Socket File
◦ -- - Ordinary file
'''

F_MODE_INV: Dict[str, int] = dict([[v,k] for k,v in F_MODE.items()])


class AndroidFileContext:
    '''对应一个Android文件系统中的文件上下文，包含一个正则表达式和一个SELinux上下文'''
    def __init__(self, regex: re.Pattern, mode: int, context: SELinuxContext):
        self.regex = regex
        '''re.Pattern 文件路径正则表达式'''
        
        self.mode = mode        # file_type可能会有的一个值： pathname_regexp [file_type] security_context 
                                # active/file_contexts 我猜测seandroid没有使用这个字段
                                
        self.context: SELinuxContext = context

    def match(self, path: str, mode: int = None) -> bool:
        if self.mode and mode:
            return (self.regex.match(path) is not None) and (mode & self.mode)
        else:
            return self.regex.match(path) is not None

    def __repr__(self):
        return "AndroidFileContext<%s -> %s>" % (self.regex.pattern, self.context)

    def __hash__(self):
        return hash(repr(self))



def read_file_contexts(source: str) -> List[AndroidFileContext]:
    '''从文件读入 *_file_context 文件'''
    with open(source, 'r') as fp:
        data = fp.read()
    contexts: List[AndroidFileContext] = []

    for line_no, line in enumerate(data.split("\n")):
        # Ignore comments and blank lines
        if re.match(r'^(\s*#)|(\s*$)', line): continue
        # greedly replace all whitespace with a single space for splitting
        line = re.sub(r'\s+', " ", line)
        # split by spaces, while eliminating empty components
        components = list(filter(lambda x: len(x) > 0, line.split(" ")))

        # regex, mode, context
        if len(components) == 3:
            regex = components[0]
            mode = F_MODE_INV[components[1]]
            context = components[2]
        # regex, context
        elif len(components) == 2:
            regex = components[0]
            context = components[1]
            mode = None
        else:
            raise ValueError("Malformed or unhandled file_contexts syntax at line %d" % (line_no+1))
        
        try:
            # we assume that the whole path much match (start of line/eol)
            # XXX: this is the right way to do this, but it breaks files which aren't
            # labeled and have no file_context's entry. We'll have to live with it for now
            regex = re.compile(r'^' + regex + r'$')
        except re.error:
            Logger.error("Invalid regex at line %d: %s" % (line_no+1, regex))
            continue
    
        context: SELinuxContext = SELinuxContext.FromString(context)
        contexts += [AndroidFileContext(regex, mode, context)]
        
    # ensure that these contexts are sorted by regex
    contexts = sorted(contexts, key=lambda x: x.regex.pattern)
    return contexts