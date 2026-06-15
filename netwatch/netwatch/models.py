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
    domain: SocketDomain
    type: SocketType
    protocol: SocketProtocol
    fd: int
    pid: int|None = None


@dataclass
class ConnectionInfo:
    """
    Connection info
    Each entry describes a variable required for connecting to a socket

    Structure:
        Connects the socket referred to by the file descriptor sockfd to the address specified by addr.
        connect(int sockfd, const struct sockaddr *addr, socketlen_t addrlen)
        connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0

    See https://man7.org/linux/man-pages/man2/connect.2.html for more information on connect calls
    """
    fd: int
    addr: dict[str, Any] # Stores sa_family, sin_port, sin_addr
    addrlen: int
    rtn_val: int # 0 = successful connection  -1 = error
    pid: int|None = None


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

    See https://man7.org/linux/man-pages/man2/open.2.html for more information on open calls
    See https://man7.org/linux/man-pages/man2/openat2.2.html for more information on openat calls (Extension of openat)
    """
    operation: FileAccessOperation
    path: str
    flags: list[str]
    ret_val: int
    dirfd: str | None = None # For openat
    pid: int | None = None
    


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
    operation: ForkOperation
    parent_pid: int
    child_pid: int
    pid: int|None = None


@dataclass
class ProcessDetails:
    pid: int
    binary_path: str | None = None
    parent_pid: int | None = None
    child_pids: list[int] = field(default_factory=list)