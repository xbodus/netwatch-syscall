"""
Analyzed parsed syscall data. Compile to link connected data
"""
from queue import Queue, Empty
from threading import Event
from .parser import SyscallParser
from .models import ParserEvent

parser = SyscallParser()

SYSCALL_ENTRIES = [] # In-Memory collection

def analyze_syscall_stream(q: Queue, event: Event) -> None:
    """
    Analyzer entrypoint
    Tails logs stored in queue from live strace feed and flags potential malicious patterns
    """
    parser = SyscallParser()

    while not event.is_set():
        try:
            parsed_data: ParserEvent = parser.parse_line(q.get(timeout=0.1))
            SYSCALL_ENTRIES.append(parsed_data)
        except (Empty, ValueError):
            continue