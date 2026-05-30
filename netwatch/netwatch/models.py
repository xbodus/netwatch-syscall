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
"""
from dataclasses import dataclass
from enum import Enum 


class SocketInfoFamily(Enum):
    AF_INET = "AF_INET"
    PF_INET = "PF_INET"

class SocketType(Enum):
    SOCK_STREAM = "SOCK_STREAM"
    SOCK_DGRAM = "SOCK_DGRAM"

class SocketInfoProtocol(Enum):
    IPPROTO_TCP = "IPPROTO_TCP"
    IPPROTO_UDP = "IPPROTO_UDP"

@dataclass
class SocketInfo:
    """
    Socket info
    Each entry decribes a variable required for making a connection

    Structure: socket(PF_INET, SOCK_STREAM, IPPROTP_TCP) = 3
    """
    family: SocketInfoFamily
    sock_type: SocketType
    protocol: SocketInfoProtocol
    fd: int  # Assigned variable of socket (i.e. socket assigned to 3). fd = file descriptor


@dataclass
class ConnectionInfo:
    """
    Connection info
    Each entry describes a variable required for connecting to a socket

    Structure: connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0
    """
    fd: int
    family: SocketInfoFamily
    port: int
    ip: str


class DataTransferOperation(Enum):
    READ = "read"
    WRITE = "write"

@dataclass
class DataTransfer:
    """
    Data Transfer (Write, Read operations)
    Each entry describes a data transfer variable

    Structure examples:  
        - write(3, "Hello World!\n", 13) = 13
        - read(3, "Boo!\n", 2048) = 5
    """
    operation: DataTransferOperation
    fd: int
    data: str
    bytes_requested: int
    bytes_transferred: int


class ProcessExecOperation(Enum):
    EXECVE = "execve"

@dataclass
class ProcessExec:
    """
    Process Exec (Process executing another process)
    Each entry decribes a variable required for execve

    Structure: execve("/usr/bin/bash", ["/usr/bin/bash"], 0x7fffc2c935f0 /* 152 vars */) = 0
    """
    operation: ProcessExecOperation
    pathname: str # Path to binary
    args: list[str] # args[0] is the name of the command being executed
    envp: str # Environment variables
    ret_val: int # Process return value (Pass:0 or Error:-1)
    pid: int | None = None # Process ID if strace is run with -f
    mem_addr: str | None = None # Memory address where the process is stored


class FileAccessOperation(Enum):
    OPEN = "open"
    OPENAT = "openat"
    READ = "read"
    WRITE = "write"
    CLOSE = "close"
    LSEEK = "lseek"

@dataclass
class FileAccess:
    """
    File Access (open, close)
    Each entry decribes a variable required for file access

    Structure:
        - open("/etc/passwd", O_RDONLY) = 3
        - openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4
    """
    operation: FileAccessOperation
    pathname: str # Path to file
    flags: list[str] # Flags used for file access
    ret_fd: int # File descriptor
    dirfd: str | None = None # Directory file descriptor
    pid: int | None = None
    


class SyscallCloseOperation(Enum):
    CLOSE = "close"

@dataclass
class SyscallClose:
    """
    Close system call
    Each entry descibes a variable in close system call marking end of operation

    Structure: close(3) = 0
    """
    fd: int
    operation: SyscallCloseOperation
    ret_val: int
    pid: int | None = None