from collections import defaultdict
import logging
from .models import (
    ParserEvent, 
    ProcessDetails, 
    SocketInfo, 
    ConnectionInfo, 
    DataTransfer, 
    DataTransferOperation,
    ProcessExec, 
    FileAccess, 
    FileAccessOperation,
    SyscallClose, 
    ProcessFork,
    FDDuplication,
    PermissionInfo,
    PermissionOperation,
    PrivilegeInfo,
    PrivilegeOperation,
    PTraceInfo,
    IOHistory,
    IOVolume,
    ConnectionVolume,
    TraceMap,
    TraceEvent,
    State,
    ThreatAlert
)
from .exceptions import StateError
from .fsm import FSM
from .rules import backdoor_fsm, dropper_fsm


logger = logging.getLogger(__name__)

class SyscallState:
    def __init__(self):
        self.active_fds: dict[int, dict[int, ParserEvent]] = defaultdict(dict) # Tracks open resources (files, sockets, pipes) Ex: {pid:{ fd:{ event details } }}
        self.processes: dict[int, ProcessDetails] = {} # Tracks metadata and lineage (which process spawned which). Ex: { pid: process details }
        self.history: dict[int, IOHistory] = {} # Tracks pid history  Dict ex: {pid: IOHistory(paths_accessed={}, paths_executed={}, active_sockfds={}, active_fds={})}  {} = sets
        self.process_execution_counts: dict[str, int] = {} # Tracks binary execution counts  Dict ex: {bin_path: 0}
        self.network_destination: dict[tuple[str, int], ConnectionVolume] = {} # Tracks network statistics  Dict ex: {(ip, port): {bytes_sent: 0, bytes_received: 0}}
        self.network_keys: dict[int, tuple[str, int]] = {} # Tracks network destination keys by pid
        self.io_volume: dict[int, IOVolume] = {} # Tracks cumulative bytes read and bytes written by a process id
        self.trace_map: dict[int, TraceMap] = {} # Tracks relationships between tracees and tracers
        self.process_fsms: dict[int, list[FSM]] = {}
        self.fd_paths: dict[int, dict[int, str]] = defaultdict(dict)

    def update(self, event: ParserEvent) -> list[ThreatAlert]:
        # Skip failed events
        if hasattr(event, "ret_val"):
            if getattr(event, "ret_val") < 0:
                return []
        elif hasattr(event, "fd"):
            if getattr(event, "fd") < 0:
                return []
        elif hasattr(event, "bytes_transferred"):
            if getattr(event, "bytes_transferred") < 0:
                return []
        elif hasattr(event, "child_pid"):
            if getattr(event, "child_pid") < 0:
                return []

        if event.pid not in self.process_fsms:
            # Initialize FSMs for pid
            bd_fsm = backdoor_fsm()
            d_fsm = dropper_fsm()

            self.process_fsms[event.pid] = [bd_fsm, d_fsm]

        alerts: list[ThreatAlert] = []

        alert_type: str | None = None

        match event:
            case SocketInfo():
                self._handle_socket(event)
                alert_type = "socket"

            case ConnectionInfo():
                self._handle_connect(event)
                connect_types = {
                    "connect": "connect",
                    "bind": "bind",
                    "listen": "listen",
                    "accept": "accept",
                    "accept4": "accept4"
                }
                alert_type = connect_types[event.operation.value]

            case DataTransfer():
                self._handle_data_transfer(event)
                data_transfer_types = {
                    "read": "read",
                    "write": "write"
                }
                alert_type = data_transfer_types[event.operation.value]

            case ProcessExec():
                self._handle_process_exec(event)
                alert_type = "execve"

            case FileAccess():
                self._handle_file_access(event)
                file_access_types = {
                    "open": "open",
                    "openat": "openat",
                    "unlink": "unlink",
                    "unlinkat": "unlinkat"
                }
                alert_type = file_access_types[event.operation.value]

            case ProcessFork():
                self._handle_fork(event)
                alert_type = "fork"

            case FDDuplication():
                self._handle_fd_dup(event)
                alert_type = "fd duplication"

            case PermissionInfo():
                self._handle_permission(event)
                alert_type = "permission"

            case PrivilegeInfo():
                self._handle_privilege(event)
                alert_type = "privilege"

            case PTraceInfo():
                self._handle_ptrace(event)
                alert_type = "ptrace"

            case SyscallClose():
                self._handle_close(event)
                alert_type = "close"

            case _:
                logger.warning(f"Unhandled event type: {type(event).__name__}")
        
        if alert_type:
            for fsm in self.process_fsms[event.pid]:
                fsm_state = fsm.transition(alert_type, event, self)
                if fsm_state == State.ALERT_TRIGGERED:
                    alerts.append(
                        ThreatAlert(
                            rule_name=fsm.name,
                            severity=fsm.severity,
                            message=f"{event.pid} Triggered Alert: {fsm.name}",
                            pid=event.pid,
                            context={}
                        )
                    )
                    fsm.reset()

        return alerts
    

    def _handle_socket(self, event: SocketInfo) -> None:
        key = event.pid
        self.active_fds[key][event.fd] = event

        if key not in self.history:
            self.history[key] = IOHistory()

        self.history[key].active_sockfds.add(event.fd)

        
    def _handle_connect(self, event: ConnectionInfo) -> None:
        self.active_fds[event.pid][event.fd] = event

        if event.addr:
            key = (event.addr["sin_addr"], event.addr["sin_port"])
            if key not in self.network_destination:
                self.network_destination[key] = ConnectionVolume()

            self.network_keys[event.pid] = key


    def _handle_data_transfer(self, event: DataTransfer) -> None:
        key: int = event.pid
        self.active_fds[key][event.fd] = event

        if key not in self.io_volume:
            self.io_volume[key] = IOVolume()

        if event.fd in self.history[key].active_sockfds: 
            if key not in self.network_keys:
                raise StateError("data transfer", "Data transferred without network key attached to PID")

            network_key: tuple[str, int] = self.network_keys[key]

            if event.operation == DataTransferOperation.READ:
                self.network_destination[network_key].bytes_received += event.bytes_transferred
        
            if event.operation == DataTransferOperation.WRITE:
                self.network_destination[network_key].bytes_sent += event.bytes_transferred
        else:
            if event.operation == DataTransferOperation.READ:
                self.io_volume[key].bytes_read += event.bytes_transferred
            
            if event.operation == DataTransferOperation.WRITE:
                self.io_volume[key].bytes_written += event.bytes_transferred


    def _handle_process_exec(self, event: ProcessExec) -> None:
        key = event.pid

        if key not in self.processes:
            self.processes[key] = ProcessDetails(
                pid=key,
                binary_path=event.pathname,
            )
        else:
            self.processes[key].binary_path = event.pathname
        
        if key not in self.history:
            self.history[key] = IOHistory()

        self.history[key].paths_executed.add(event.pathname)
        self.process_execution_counts[event.pathname] = self.process_execution_counts.get(event.pathname, 0) + 1


    def _handle_file_access(self, event: FileAccess) -> None:
        key = event.pid
        self.active_fds[key][event.ret_val] = event
        self.fd_paths[key][event.ret_val] = event.path

        if key not in self.history:
            self.history[key] = IOHistory()

        self.history[key].paths_accessed.add(event.path)

        if event.operation in [FileAccessOperation.OPEN, FileAccessOperation.OPENAT]:
            self.history[key].active_fds.add(event.fd)
        
        if event.operation in [FileAccessOperation.UNLINK, FileAccessOperation.UNLINKAT]:
            self.history[key].active_fds.discard(event.fd)


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


    def _handle_fd_dup(self, event: FDDuplication) -> None:
        key = event.pid
        self.active_fds[key][event.newfd] = event

        if key not in self.history:
            self.history[key] = IOHistory()

        if event.oldfd in self.history[key].active_fds:
            self.history[key].active_fds.add(event.newfd)
        
        if event.oldfd in self.history[key].active_sockfds:
            self.history[key].active_sockfds.add(event.newfd)

        if event.oldfd in self.fd_paths[key]:
            self.fd_paths[key][event.newfd] = self.fd_paths[key][event.oldfd]


    def _handle_permission(self, event: PermissionInfo) -> None:
        if event.pid not in self.history:
            self.history[event.pid] = IOHistory()
        
        if event.operation == PermissionOperation.FCHMOD:
            path = self.fd_paths[event.pid].get(event.fd)
            if path:
                self.history[event.pid].paths_accessed.add(path)
        else:
            self.history[event.pid].paths_accessed.add(event.path)


    def _handle_privilege(self, event: PrivilegeInfo) -> None:
        if event.pid not in self.processes:
            self.processes[event.pid] = ProcessDetails(
                pid=event.pid,
            )

        if event.operation == PrivilegeOperation.SETUID:
            self.processes[event.pid].uid = event.uid
        elif event.operation == PrivilegeOperation.SETGID:
            self.processes[event.pid].gid = event.gid
        elif event.operation == PrivilegeOperation.SETREUID:
            self.processes[event.pid].ruid = event.ruid
            self.processes[event.pid].euid = event.euid
        elif event.operation == PrivilegeOperation.SETREGID:
            self.processes[event.pid].rgid = event.rgid
            self.processes[event.pid].egid = event.egid 


    def _handle_ptrace(self, event: PTraceInfo) -> None:
        if event.op in ["PTRACE_ATTACH", "PTRACE_SEIZE"]:
            self.trace_map[event.pid] = TraceMap(
                tracee=event.t_pid,
                tracer=event.pid
            )
        elif event.op == "PTRACE_DETACH":
            if event.pid in self.trace_map and event.t_pid == self.trace_map[event.pid].tracee:
                self.trace_map.pop(event.pid)
        elif event.op in ["PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_SETREGS"]:
            if event.pid in self.trace_map and self.trace_map[event.pid].tracee == event.t_pid:
                if event.pid not in self.history:
                    self.history[event.pid] = IOHistory()

                t_event = TraceEvent(
                    op=event.op,
                    tracee=event.t_pid,
                    tracer=event.pid
                )

                self.history[event.pid].trace_executed.add(t_event)
            else:
                # Invalid sequence of events. Trigger alert
                pass


    def _handle_close(self, event: SyscallClose) -> None:
        key = event.pid
        self.active_fds[key].pop(event.fd, None)
        self.fd_paths[key].pop(event.fd, None)

        if key in self.history:
            if event.fd in self.history[key].active_fds:
                self.history[key].active_fds.discard(event.fd)