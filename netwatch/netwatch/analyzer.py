"""
Analyzed parsed syscall data. Compile to link connected data
"""

from .parser import SyscallParser

parser = SyscallParser()

SYSCALL_ENTRIES = [] # In-Memory collection

def analyze_syscall_stream(file):
    """
    Analyzer entrypoint
    Tails file from live strace feed and flags potential malicious patterns
    """
    with open() as f:
        pass
    
    