"""
"""
from typing import Any, Callable, TYPE_CHECKING
from .fsm import FSM
from .models import (
    State, 
    Severity,
    SocketInfo,
    SocketDomain,
    SocketType,
    SocketProtocol,
    ConnectionInfo,
    ConnectionOperation,
    FDDuplication,
    FDDuplicationOperation,
    ProcessExec,
    FileAccess,
    PermissionInfo
)

if TYPE_CHECKING:
    from .state import SyscallState

def backdoor_fsm() -> FSM:
    """Creates FSM to track processes suspected of backdoor creation"""

    fsm = FSM(
        name="Inbound Backdoor Listener",
        severity=Severity.CRITICAL
    )

    # Event 1: Socket created
    creation_condition: Callable[[SocketInfo, "SyscallState"], bool] = lambda event, state_store: event.domain in [SocketDomain.AF_INET, SocketDomain.AF_INET6] and event.type == SocketType.SOCK_STREAM
    fsm.add_transition(State.INIT, "socket", State.SOCKET_CREATED, creation_condition)
    
    # Event 2: Process binds to socket
    fsm.add_transition(State.SOCKET_CREATED, "bind", State.PORT_BOUND)
    
    # Event 3: Socket listens for outside connections
    fsm.add_transition(State.PORT_BOUND, "listen", State.LISTENING)

    # Event 4: Outside connection established
    connect_condition: Callable[[ConnectionInfo, "SyscallState"], bool] = lambda event, state_store: event.operation == ConnectionOperation.CONNECT and event.ret_val != -1
    fsm.add_transition(State.LISTENING, "connect", State.CONNECTION_ACCEPTED, connect_condition)

    # Event 5: Socket obsfucated from normal fd
    redirect_condition: Callable[[FDDuplication, "SyscallState"], bool] = lambda event, state_store: event.oldfd != event.newfd
    fsm.add_transition(State.CONNECTION_ACCEPTED, "fd duplication", State.STREAMS_REDIRECTED, redirect_condition)

    # Event 6: Check if shell process is started for remote commands
    alert_condition: Callable[[ProcessExec, "SyscallState"]] = lambda event, state_store: event.pathname.endswith(("sh", "bash", "zsh", "dash"))
    fsm.add_transition(State.STREAMS_REDIRECTED, "execve", State.ALERT_TRIGGERED, alert_condition)

    return fsm


def dropper_fsm() -> FSM:
    """Create FSM to track processes suspected of payload droppers"""
    fsm = FSM(
        name="Payload Dropper",
        severity=Severity.HIGH
    )

    # Event 1: Check files opened in suspicious locations
    open_condition: Callable[[FileAccess, "SyscallState"], bool] = lambda event, state_store: event.path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
    fsm.add_transition(State.INIT, "open", State.FILE_CREATED, open_condition)

    # Event 2: Checks for bytes written to path
    fsm.add_transition(State.FILE_CREATED, "write", State.FILE_WRITTEN)

    # Event 3: Check for permission changes
    permission_condition: Callable[[PermissionInfo, "SyscallState"], bool] = lambda event, state_store: event.mode & 73 and event.path in state_store.history[event.pid].paths_accessed
    fsm.add_transition(State.FILE_WRITTEN, "permission", State.MODE_ESCALATED, permission_condition)

    # Event 4: Trigger alert if suspicious file has been executed
    alert_condition: Callable[[ProcessExec, "SyscallState"], bool] = lambda event, state_store: event.pathname in state_store.history[event.pid].paths_accessed
    fsm.add_transition(State.MODE_ESCALATED, "execve", State.ALERT_TRIGGERED, alert_condition)