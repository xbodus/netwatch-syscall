"""
Parse strace output for analyzing
"""

from ast import pattern
import re
import logging
from .models import SocketInfo, ConnectionInfo, DataTransfer, ProcessExec, FileAccess, SyscallClose, FileAccessOperation, SyscallCloseOperation, ProcessExecOperation, ParserEvent, ProcessFork, ForkOperation


logger = logging.getLogger(__name__)


class SyscallParser:
    def __init__(self, default_pid:int = 0):
        self.default_pid = default_pid # Default set for single process traces
        self.registry = {
            "socket": self.parse_socket,
            "connect": self.parse_connection,
            "write": self.parse_data,
            "read": self.parse_data,
            "execve": self.parse_procexec,
            "open": self.parse_file_access,
            "openat": self.parse_file_access,
            "close": self.parse_close,
            "fork": self.parse_fork,
            "clone": self.parse_fork,
            "vfork": self.parse_fork,
            "clone3": self.parse_fork
        }


    def parse_line(self, line: str) -> ParserEvent:
        """
        Extract the system call name and route it to the appropriate parser
        """
        clean_line = line.strip()

        pid = self.default_pid
        pid_pattern = r'^(\d+|\[\d+\]|\[pid\s+\d+\])\s+(.*)'
        pid_match = re.search(pid_pattern, clean_line, flags=re.DOTALL)


        if pid_match:
            pid_str, clean_line = pid_match.groups()
            pid = int(re.sub(r'\D', '', pid_str)) # sub anythin that is not a digit

        event = self._parse_syscall(clean_line)
        event.pid = pid
        if isinstance(event, ProcessFork):
            event.parent_pid = pid
        return event


    def _parse_syscall(self, line) -> ParserEvent:
        """
        Helper method to route line to proper parser
        """
        syscall_pattern = r'^([a-z0-9_]+)\('
        match = re.search(syscall_pattern, line)

        if not match:
            raise ValueError("Unable to identify system call prefix")

        syscall_name = match.group(1)
        method = self.registry.get(syscall_name)

        if not method:
            raise ValueError(f"No parser method registered for system call: {syscall_name}")

        return method(line)


    def parse_socket(self, line: str) -> SocketInfo:
        """
        Parse socket info

        Example: socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
        """
        pattern = r'socket\((.+), (.+), (.+)\) = (\d+)'
        match = re.match(pattern, line)

        if match:
            family, sock_type, protocol, fd = match.groups()
            return SocketInfo(domain=family, type=sock_type, protocol=protocol, fd=int(fd))
        
        logger.warning(f"[ERROR] Failed to parse socket: {line}")
        raise ValueError("Unable to parse socket info")


    def parse_connection(self, line: str) -> ConnectionInfo:
        """
        Parse connection info

        Example: connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0
        """
        pattern = r'connect\((\d+), \{.+=(.+), .+=.+\((\d+)\), .+=.+\("(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"\)\}, (\d+)\) = (\d+)'
        match = re.match(pattern, line)

        if match:
            fd, family, port, ip, addrlen, rtn_val = match.groups()
            return ConnectionInfo(
                fd=int(fd), 
                addr={
                    "sa_family": family,
                    "sin_port": int(port),
                    "sin_addr": ip
                },
                addrlen=int(addrlen),
                ret_val=int(rtn_val)
                )

        logger.warning(f"[ERROR] Failed to parse connect: {line}")
        raise ValueError("Unable to parse connection info")


    def parse_data(self, line: str) -> DataTransfer:
        """
        Parse Data Transfer (Write/Read Operations)

        Examples:  
            - write(3, "Hello World!\n", 13) = 13
            - read(3, "Boo!\n", 2048) = 5
        """
        pattern = r'([a-z]+)\((\d+), "([^"]*)", (\d+)\) = (\d+)'
        match = re.match(pattern, line)
        
        if match:
            operation, fd, data, bytes_requested, bytes_transferred = match.groups()
            return DataTransfer(
                operation=operation, 
                fd=int(fd), 
                data=data, 
                bytes_requested=int(bytes_requested), 
                bytes_transferred=int(bytes_transferred)
            )

        logger.warning(f"[ERROR] Failed to parse data transfer: {match}")
        raise ValueError("Unable to parse data transfer")


    def parse_procexec(self, line: str) -> ProcessExec:
        """
        Parse Process Exec (Process executing another process)

        Structure examples:
            - execve("/usr/bin/bash", ["/usr/bin/bash"], 0x7fffc2c935f0 /* 152 vars */) = 0
            - execve("/bin/sh", ["sh", "-i"], [/* 24 vars */]) = 0
        """
        pattern = r'execve\("([^"]+)", \[(.*)\], (.*?)\) = (-?\d+)'
        match = re.match(pattern, line)
        
        if match:
            pathname, args_raw, envp_raw, ret_val = match.groups()
            args = [a.strip('"') for a in args_raw.split(", ")] if args_raw else []
            return ProcessExec(
                operation=ProcessExecOperation.EXECVE,
                pathname=pathname,
                args=args,
                envp=envp_raw,
                ret_val=int(ret_val)
            )
        
        logger.warning(f"[ERROR] Failed to parse process exec: {line}")
        raise ValueError("Unable to parse process exec")


    def parse_file_access(self, line: str) -> FileAccess:
        """
        Parse File Access (open, close)

        Examples:
            - open("/etc/passwd", O_RDONLY) = 3
            - openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4
        """
        # int openat(int dirfd, const char *path, int flags, ... /* mode_t mode */ )
        pattern = r'(open|openat)\((?:([^,]+), )?"([^"]+)", ([A-Z_|]+)\) = (\d+)'
        match = re.match(pattern, line)
        
        if match:
            operation, dirfd, pathname, flags_raw, ret_fd = match.groups()
            flags = [flag.strip('"') for flag in flags_raw.split("|")] if flags_raw else []
            return FileAccess(
                operation=FileAccessOperation(operation),
                dirfd=dirfd,
                path=pathname, 
                flags=flags,
                ret_val=int(ret_fd),
            )

        logger.warning(f"[ERROR] Failed to parse file access: {line}")
        raise ValueError("Unable to parse file access")

    
    def parse_fork(self, line: str) -> ProcessFork:
        """
        Parse fork/clone system calls

        Example: 
            - 1000  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, ...) = 1001
            - 1000  fork() = 1001
        """
        pattern = r'^(fork|clone|vfork|clone3)\(.*\)\s+=\s+(\d+)'
        match = re.search(pattern, line)

        if match:
            operation, child_pid = match.groups()
            return ProcessFork(
                operation=ForkOperation(operation),
                parent_pid=0,
                child_pid=int(child_pid)
            )
        
        logger.warning(f"[ERROR] Failed to parse {line}")
        raise ValueError("Unable to parse fork/clone")


    def parse_close(self, line: str) -> SyscallClose:
        """
        Parse close system call

        Example: close(3) = 0
        """
        pattern = r'close\((\d+)\) = (-?\d+)'
        match = re.match(pattern, line)
        
        if match:
            fd, ret_val = match.groups()
            return SyscallClose(
                fd=int(fd), 
                operation=SyscallCloseOperation.CLOSE,
                ret_val=int(ret_val)
            )

        logger.warning(f"[ERROR] Failed to parse close: {line}")
        raise ValueError("Unable to parse close")