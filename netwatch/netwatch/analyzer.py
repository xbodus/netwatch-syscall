"""
Analyzed parsed syscall data. Compile to link connected data
Ex: 
    - "Process 1024 opened /tmp/payload and got File Descriptor 4"
    - "Process 1024 executed /bin/sh"
    - "Process 1024 closed File Descriptor 4"
"""
from queue import Queue, Empty
from threading import Event
import logging
from .parser import SyscallParser
from .models import ParserEvent, ThreatAlert
from .state import SyscallState
from .exceptions import ParserError, LexerError, StateError

logger = logging.getLogger(__name__)

parser = SyscallParser()


def analyze_syscall_stream(q: Queue, event: Event, state: SyscallState = None) -> None:
    """
    Analyzer entrypoint
    Tails logs stored in queue from live strace feed and flags potential malicious patterns
    """
    parser = SyscallParser()

    if not state:
        state = SyscallState()

    while not event.is_set():
        try:
            line = q.get(timeout=0.1)
            parsed_data: ParserEvent = parser.parse_line(line)
            alerts: list[ThreatAlert] = state.update(parsed_data, line)
            if len(alerts) > 0:
                for alert in alerts:
                    logger.warning(f"[{alert.severity}] {alert.message}")
        except (Empty, ParserError, LexerError, StateError) as e:
            if not isinstance(e, Empty):
                logger.warning(f"[ERROR] Analyzer Error: {e}")
            continue