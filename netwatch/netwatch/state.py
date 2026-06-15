from collections import defaultdict
import logging
from .models import ParserEvent, ProcessDetails, SocketInfo, ConnectionInfo, DataTransfer, ProcessExec, FileAccess, SyscallClose, ProcessFork


logger = logging.getLogger(__name__)

class SyscallState:
    def __init__(self):
        self.active_fds: dict[int, dict[int, ParserEvent]] = defaultdict(dict) # Tracks open resources (files, sockets, pipes) Ex: pid:{ fd:{ event details } }
        self.processes: dict[int, ProcessDetails] = {} # Tracks metadata and lineage (which process spawned which). Ex: { pid: process details }
        # Potential add I/O history store

    def update(self, event: ParserEvent) -> None:
        match event:
            case SocketInfo():
                self._handle_socket(event)
            case ConnectionInfo():
                self._handle_connect(event)
            case DataTransfer():
                self._handle_data_transfer(event)
            case ProcessExec():
                self._handle_process_exec(event)
            case FileAccess():
                self._handle_file_access(event)
            case ProcessFork():
                self._handle_fork(event)
            case SyscallClose():
                self._handle_close(event)
            case _:
                logger.warning(f"Unhandled event type: {type(event).__name__}")
    
    # Internal methods to update syscall state
    def _handle_socket(self, event: SocketInfo) -> None:
        self.active_fds[event.pid][event.fd] = event
        
    def _handle_connect(self, event: ConnectionInfo) -> None:
        self.active_fds[event.pid][event.fd] = event

    def _handle_data_transfer(self, event: DataTransfer) -> None:
        self.active_fds[event.pid][event.fd] = event

    def _handle_process_exec(self, event: ProcessExec) -> None:
        if event.pid in self.processes:
            self.processes[event.pid].binary_path = event.pathname
        else:
            self.processes[event.pid] = ProcessDetails(
                pid=event.pid,
                binary_path=event.pathname,
            )

    def _handle_file_access(self, event: FileAccess) -> None:
        self.active_fds[event.pid][event.ret_val] = event

    def _handle_fork(self, event: ProcessFork) -> None:
        parent_pid = event.parent_pid
        child_pid = event.child_pid

        if parent_pid not in self.processes:
            self.processes[parent_pid] = ProcessDetails(
                pid=parent_pid,
                binary_path="Unknown"
            )

        self.processes[parent_pid].child_pids.append(child_pid)

        parent_path = self.processes[parent_pid].binary_path
        self.processes[child_pid] = ProcessDetails(
            pid=child_pid,
            binary_path=parent_path,
            parent_pid=parent_pid
        )

    def _handle_close(self, event: SyscallClose) -> None:
        self.active_fds[event.pid].pop(event.fd, None)