#!/usr/bin/env python3

__author__ = "Md. Ahsan Ayub"
__license__ = "GPL"
__credits__ = ["Ayub, Md. Ahsan", "Siraj, Ambareen"]
__maintainer__ = "Md. Ahsan Ayub"
__email__ = "mayub42@tntech.edu"
__status__ = "Prototype"


class SuspiciousImports(object):
    ''' The purpose of this class is to accumulate a list of suspicious
    import categories by ransomware samples based on the domain knowledge.
    The object of this class can access all the items in the list. '''
    
    def __init__(self):
        ''' Initialize the container with a list of suspicious imports. '''
        
        self._suspicious_imports = ["cursor", "mouse", "file", "clipboard",
                                "delete", "process", "thread", "desktop",
                                "window", "monitor", "service", "reg",
                                "internet", "http", "ftp", "url", "icmp",
                                "environment", "isdebugger", "heap", "execute"]
        
    def get_suspicious_imports(self) -> list:
        ''' Return the knowledge base in list '''
        return self._suspicious_imports
     

    def __str__(self) -> str:
        ''' Return the string of items enlisted in the suspicious imports '''
        return str(self._suspicious_imports)
    
    
    def __len__(self) -> int:
        ''' Return the length of the knowledge base list '''
        return len(self._suspicious_imports)