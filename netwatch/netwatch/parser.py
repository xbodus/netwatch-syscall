"""
Parse strace output for analyzing
"""

import re
from .models import SocketInfo, ConnectionInfo, DataTransfer, ProcessExec, FileAccess, SyscallClose, FileAccessOperation, SyscallCloseOperation, ProcessExecOperation, ParserEvent


class SyscallParser:
    def __init__(self):
        self.registry = {
            "socket": self.parse_socket,
            "connect": self.parse_connection,
            "write": self.parse_data,
            "read": self.parse_data,
            "execve": self.parse_procexec,
            "open": self.parse_file_access,
            "openat": self.parse_file_access,
            "close": self.parse_close
        }


    def parse_line(self, line: str) -> ParserEvent:
        """
        Extract the system call name and route it to the appropriate parser
        """
        pattern = r'^([a-z0-9_]+)\('
        match = re.search(pattern, line.strip())

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
            return SocketInfo(family=family, sock_type=sock_type, protocol=protocol, fd=int(fd))
        raise ValueError("Unable to parse socket info")


    def parse_connection(self, line: str) -> ConnectionInfo:
        """
        Parse connection info

        Example: connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0
        """
        pattern = r'connect\((\d+), \{.+=(.+), .+=.+\((\d+)\), .+=.+\("(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"\)\}, \d+\) = \d+'
        match = re.match(pattern, line)

        if match:
            fd, family, port, ip = match.groups()
            return ConnectionInfo(fd=int(fd), family=family, port=int(port), ip=ip)
        raise ValueError("Unable to parse connection info")


    def parse_data(self, line: str) -> DataTransfer:
        """
        Parse Data Transfer (Write/Read Operations)

        Examples:  
            - write(3, "Hello World!\n", 13) = 13
            - read(3, "Boo!\n", 2048) = 5
        """
        pattern = r'([a-z]+)\((\d+), "(.+\n)", (\d+)\) = (\d+)'
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
                pathname=pathname, 
                flags=flags,
                ret_fd=int(ret_fd),
            )
        raise ValueError("Unable to parse file access")


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
        raise ValueError("Unable to parse close")