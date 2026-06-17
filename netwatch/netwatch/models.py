"""
Define project data structures in data classes

Example:

    @dataclass
    class ConnectionInfo:
        fd: int
        ip: str
        port: int
        bytes_sent: int = 0
        bytes_received: int = 0
        
        # You CAN add methods!
        def total_bytes(self) -> int:
            return self.bytes_sent + self.bytes_received
        
        def is_high_volume(self, threshold: int = 10000) -> bool:
            return self.total_bytes() > threshold

Use case example:    
    conn = ConnectionInfo(fd=3, ip="192.168.10.1", port=5555)
    print(conn.ip)

Dataclasses for syscall data (SocketInfo, ConnectionInfo, DataTransfer)

See https://man7.org/linux/man-pages/man1/strace.1.html for more information on strace
"""
from typing import Any
from dataclasses import dataclass, field
from enum import Enum 


type ParserEvent = SocketInfo | ConnectionInfo | DataTransfer | ProcessExec | FileAccess | SyscallClose | ProcessFork

class SocketOperation(Enum):
    SOCKET = "socket"

class SocketDomain(Enum):
    AF_UNIX = "AF_UNIX" # Local link
    PF_UNIX = "PF_UNIX" # Synonym AF_UNIX
    AF_LOCAL = "AF_LOCAL" # Synonym AF_UNIX
    AF_INET = "AF_INET" # Ipv4
    PF_INET = "PF_INET" # Ipv4
    PF_INET6 = "PF_INET6" # Ipv6
    AF_INET6 = "AF_INET6" # Ipv6
    AF_NETLINK = "AF_NETLINK" # Kernel user interface device communication
    PF_NETLINK = "PF_NETLINK" # Kernel user interface device communication
    PF_PACKET = "PF_PACKET" # Direct access to device layer
    AF_PACKET = "AF_PACKET" # Direct access to device layer
    AF_BLUETOOTH = "AF_BLUETOOTH"

class SocketType(Enum):
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"
    SOCK_SEQPACKET = "SOCK_SEQPACKET"
    SOCK_RAW = "SOCK_RAW"
    SOCK_RDM = "SOCK_RDM"
    SOCK_PACKET = "SOCK_PACKET" # Obsolete. Potential security risk as it requires root access and captures all communications through socket. Replaced by PF_PACKET/AF_PACKET
    SOCK_NONBLOCK = "SOCK_NONBLOCK"
    SOCK_CLOEXEC = "SOCK_CLOEXEC"


class SocketProtocol(Enum):
    IPPROTO_TCP = "IPPROTO_TCP" # 0
    IPPROTO_UDP = "IPPROTO_UDP" # 17
    IPPROTO_ICMP = "IPPROTO_ICMP" # 1
    IPPROTO_RAW = "IPPROTO_RAW" # 255

@dataclass
class SocketInfo:
    """
    Socket info
    Each entry decribes a variable required for making a connection

    Structure: 
        Creates an endpoint for communication and returns a file descriptor that refers to that endpoint.
        socket(int domain, int type, int protocol) = file descriptor
        socket(PF_INET, SOCK_STREAM, IPPROTP_TCP) = 3
    
    See https://man7.org/linux/man-pages/man2/socket.2.html for more information on socket calls
    """
    operation: SocketOperation
    domain: SocketDomain
    type: SocketType
    protocol: SocketProtocol
    fd: int
    pid: int|None = None


class ConnectionOperation(Enum):
    CONNECT = "connect"
    BIND = "bind"
    LISTEN = "listen"
    ACCEPT = "accept"
    ACCEPT4 = "accept4"

@dataclass
class ConnectionInfo:
    """
    Connection info
    Each entry describes a variable required for connecting to a socket

    Structure:
        Connects the socket referred to by the file descriptor sockfd to the address specified by addr.
        connect(int sockfd, const struct sockaddr *addr, socketlen_t addrlen) = return value (returns success (0) or error (-1))
        connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0

        Assigns the address specified by addr to the socket referred to by the file descriptor sockfd.
        bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = return value (returns success (0) or error (-1))
        bind(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 0

        Marks the socket referred to by sockfd as a passive socket, that is, as a socket that will be used to accept incoming connection requests using accept(2).
        listen(int sockfd, int backlog) = return value (returns success (0) or error (-1))
        listen(3, 128) = 0

        Used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET).  It extracts the first connection request on the queue of pending connections for the listening socket, sockfd, creates a new connected socket, and returns a new file descriptor referring to that socket.
        accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen) = return value (returns new fd for incoming connection or error (-1))
        accept(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 4

        accept4(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen, int flags) = return value (returns new fd or error (-1))
        accept4(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16, SOCK_NONBLOCK) = 4

    See https://man7.org/linux/man-pages/man2/connect.2.html for more information on connect calls
    See https://man7.org/linux/man-pages/man2/bind.2.html for more information on bind calls
    See https://man7.org/linux/man-pages/man2/listen.2.html for more information on listen calls
    See https://man7.org/linux/man-pages/man2/accept.2.html for more information on accept/accept4 calls
    """
    operation: ConnectionOperation
    sockfd: int
    ret_val: int
    pid: int | None = None
    addr: dict[str, Any] | None = None # Stores sa_family, sin_port, sin_addr
    addrlen: int | None = None
    backlog: int | None = None
    flags: list[str] | None = None

    @property
    def fd(self) -> int:
        return self.sockfd


class DataTransferOperation(Enum):
    READ = "read"
    WRITE = "write"

@dataclass
class DataTransfer:
    """
    Data Transfer (Write, Read operations)
    Each entry describes a data transfer variable. Tracks network data transfer operations over socket connections (operations over socket fd).

    Structure examples:
        Writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.
        write(int file descriptor, const void buf[count], size_t count) = return value (bytes written or error (-1))
        write(3, "Hello World!\n", 13) = 13

        Attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
        read(int file descriptor, void buf[count], size_t count) = return value (bytes read or error (-1))
        read(3, "Boo!\n", 2048) = 5
    
    See https://man7.org/linux/man-pages/man2/write.2.html for more information on write calls
    See https://man7.org/linux/man-pages/man2/read.2.html for more information on read calls
    """
    operation: DataTransferOperation
    fd: int
    data: str
    bytes_requested: int
    bytes_transferred: int
    pid: int|None = None


class ProcessExecOperation(Enum):
    EXECVE = "execve"

@dataclass
class ProcessExec:
    """
    Process Exec (Process executing another process)
    Each entry decribes a variable required for execve

    Structure: 
        Executes the program referred to by path. This causes the program that is currently being run by the calling process to be replaced with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments.
        execve(const char *path, char *const _Nullable argv[], char *const _Nullable envp[]) = return value (Does not return on success (0) and returns -1 on error)
        execve("/usr/bin/bash", ["/usr/bin/bash"], 0x7fffc2c935f0 /* 152 vars */) = 0

    See https://man7.org/linux/man-pages/man2/execve.2.html for more information on execve calls
    """
    operation: ProcessExecOperation
    pathname: str
    args: list[str] # args[0] is the name of the command being executed
    envp: str
    ret_val: int
    pid: int | None = None
    mem_addr: str | None = None


class FileAccessOperation(Enum):
    OPEN = "open"
    OPENAT = "openat"
    UNLINK = "unlink"
    UNLINKAT = "unlinkat"

@dataclass
class FileAccess:
    """
    File Access
    Each entry decribes a variable required for file access. Tracks disk operations (operations to file fd).

    Structure:
        System call opens the file specified by path.
        Open file
        open(const char *path, int flags, ..., /* mode_t mode */) = return value
        open("/etc/passwd", O_RDONLY) = 3 (returns file descriptor or error (-1))

        Open file at specified directory fd
        openat(int dirfd, const char *path, int flags, ..., /* mode_t mode */) = return value
        openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4

        Deletes a name from the filesystem.
        unlink(const char *path) = return value (returns success (0) or error (-1))
        unlink("/tmp/payload") = 0

        Operates in exactly the same way as either unlink() except at specified diretory fd
        unlinkat(int dirfd, const char *path, int flags) = return value (returns success (0) or error (-1))
        unlinkat(AT_FDCWD, "example.txt", 0) = 0

    See https://man7.org/linux/man-pages/man2/open.2.html for more information on open calls
    See https://man7.org/linux/man-pages/man2/openat2.2.html for more information on openat calls (Extension of openat)
    """
    operation: FileAccessOperation
    path: str
    ret_val: int
    pid: int | None = None
    dirfd: str | None = None
    flags: list[str] | None = None

    @property
    def fd(self) -> int:
        return self.sockfd
    


class SyscallCloseOperation(Enum):
    CLOSE = "close"

@dataclass
class SyscallClose:
    """
    Close system call
    Each entry descibes a variable in close system call marking end of operation

    Structure: 
        Closes a file descriptor, so that it no longer refers to any file and may be reused.
        close(int fd) = return value (returns success (0) or error (-1))
        close(3) = 0
    
    See https://man7.org/linux/man-pages/man2/close.2.html for more information on close calls.
    """
    operation: SyscallCloseOperation
    fd: int
    ret_val: int
    pid: int | None = None


class ForkOperation(Enum):
    CLONE = "clone"
    CLONE3 = "clone3"
    FORK = "fork"
    VFORK = "vfork"

@dataclass
class ProcessFork:
    """
    Fork/Clone system call
    Each entry descibes a variable in fork/clone system call spawning new process

    Structure: 
        Creates a new process by duplicating the calling process.
        fork(void) = return value (returns child pid or error (-1))
        fork() = 1001

        These system calls create a new ("child") process, in a manner similar to fork(2).
        clone(typeof(int (void *_Nullable)) *fn,
                 void *stack,
                 int flags,
                 void *_Nullable arg, ...
                 /* pid_t *_Nullable parent_tid,
                    void *_Nullable tls,
                    pid_t *_Nullable child_tid */) = return value (returns child pid or error (-1))
        clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, ...) = 1001

    See https://man7.org/linux/man-pages/man2/fork.2.html for more information on fork calls
    See https://man7.org/linux/man-pages/man2/clone.2.html for more information on clone calls
    """
    operation: ForkOperation
    parent_pid: int
    child_pid: int
    pid: int|None = None


class PermissionOperation(Enum):
    CHMOD = "chmod"
    FCHMOD = "fchmod"
    FCHMODAT = "fchmodat"

@dataclass
class PermissionInfo:
    """
    chmod/fchmod system call
    Each entry describes a variable in chmod/fchmod system call changing permissions

    Structure:
        The chmod() and fchmod() system calls change a file's mode bits.

        Depreciated for fchmodat in newer 64-bit systems
        chmod(const char *path, mode_t mode) = return value (returns success (0) or error (-1))
        chmod("file", 0644) = 0

        Follows openat syscall to change mode of open file
        fchmod(int fd, mode_t mode) = return value (returns success (0) or error (-1))
        fchmod(3, 0644) = 0

        Standard chmod default syscall. Follows execve syscall calling chmod binary
        fchmodat(int dirfd, const char *path, mode_t mode, int flags) = return value (returns success (0) or error (-1))
        fchmodat(AT_FDCWD, "file.txt", 0644) = 0

    See https://man7.org/linux/man-pages/man2/chmod.2.html for more information on chmod/fchmod calls
    """
    operation: PermissionOperation
    mode: int
    ret_val: int
    pid: int | None = None
    fd: int | None = None
    dirfd: str | None = None
    path: str | None = None
    flags: list[str] | None = None


class FDDuplicationOperation(Enum):
    DUP = "dup"
    DUP2 = "dup2"
    DUP3 = "dup3"

@dataclass
class FDDuplication:
    """
    dup/dup2/dup3 system call
    Each entry descibes a variable in dup/dup2/dup3 system call duplication file descriptors

    Structure:
        Allocates a new file descriptor that refers to the same open file description as the descriptor oldfd.

        Uses the lowest fd available as newfd
        dup(int oldfd) = return value (returns new fd or error (-1))
        dup(3) = 0

        Uses the file descriptor passed as newfd
        dup2(int oldfd, int newfd) = return value (returns new fd or error (-1))
        dup2(3, 0) = 0

        Uses the file descriptor passed as newfd with flags passed
        dup3(int oldfd, int newfd, int flags) = return value (returns new fd or error (-1))
        dup3(3, 0, O_CLOEXEC) = 0

    See https://man7.org/linux/man-pages/man2/dup.2.html for more information on dup/dup2/dup3 calls
    """
    operation: FDDuplicationOperation
    oldfd: int
    ret_value: int
    pid: int | None = None
    newfd: int | None = None
    flags: list[str] | None = None


class PrivilegeOperation(Enum):
    SETUID = "setuid"
    SETGID = "setgid"
    SETREUID = "setreuid"
    SETREGID = "setregid"

@dataclass
class PrivilegeInfo:
    """
    setuid/setgid/setreuid system call
    Each entry descibes a variable in setuid/setgid/setreuid system call to set real or effective user/group id

    Structure:
        Sets the effective user ID of the calling process.
        setuid(uid_t uid) = return value (returns success (0) or error (-1))
        setuid(0) = 0

        Sets the effective group ID of the calling process.
        setgid(gid_t gid) = return value (returns success (0) or error (-1))
        setgid(0) = 0

        Sets real and effective user IDs of the calling process.
        setreuid(uid_t ruid, uid_t euid) = return value (returns success (0) or error (-1))
        setreuid(1000, 1000) = 0

        setregid(gid_t rgid, gid_t egid) = return value (returns success (0) or error (-1))
        setregid(1000, 1000) = 0

    See https://man7.org/linux/man-pages/man2/setuid.2.html for more information on setuid calls
    """
    operation: PrivilegeOperation
    ret_val: int
    pid: int | None = None
    uid: int | None = None
    gid: int | None = None
    ruid: int | None = None
    euid: int | None = None
    rgid: int | None = None
    egid: int | None = None
    

class PTraceOperation(Enum):
    PTRACE = "ptrace"

@dataclass
class PTraceInfo:
    """
    ptrace system call
    Each entry descibes a variable in ptrace system call to trace tracee process

    Structure:
        System call provides a means by which one process (the "tracer") may observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers.
        ptrace(enum __ptrace_request op, pid_t pid, void *addr, void *data) = return value (return value dependent of flag used, success (0), or error (-1))
        ptrace(PTRACE_ATTACH, target_pid, ...) or ptrace(PTRACE_TRACEME, ...)
        ptrace(PTRACE_ATTACH, 12345, NULL, NULL) = 0

    See https://man7.org/linux/man-pages/man2/ptrace.2.html for more information on ptrace calls
    """
    operation: PTraceOperation
    op: str
    t_pid: int
    ret_val: int
    pid: int | str | None = None
    addr: str | None = None # Verify sample addr
    data: str | None = None # Verify sample data



@dataclass
class ProcessDetails:
    pid: int
    binary_path: str | None = None
    parent_pid: int | None = None
    child_pids: list[int] = field(default_factory=list)