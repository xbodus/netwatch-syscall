"""
Parse strace output for analyzing
"""

import re
import logging
from .models import (
    SocketInfo, 
    SocketOperation,
    SocketDomain,
    SocketProtocol,
    SocketType,
    ConnectionInfo, 
    ConnectionOperation,
    DataTransfer,
    DataTransferOperation, 
    ProcessExec, 
    FileAccess, 
    SyscallClose, 
    FileAccessOperation, 
    SyscallCloseOperation, 
    ProcessExecOperation, 
    ParserEvent, 
    ProcessFork, 
    ForkOperation,
    PermissionInfo,
    PermissionOperation,
    FDDuplication,
    FDDuplicationOperation,
    PrivilegeInfo,
    PrivilegeOperation,
    PTraceInfo,
    PTraceOperation
)


logger = logging.getLogger(__name__)


class SyscallParser:
    def __init__(self, default_pid:int = 0):
        self.default_pid = default_pid # Default set for single process traces


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

        event = self._parse_syscall(clean_line, pid)

        return event


    def _parse_syscall(self, line: str, pid: int) -> ParserEvent:
        """
        Helper method to route line to proper parser
        """
        syscall_pattern = r'^([a-z0-9_]+)\('
        match = re.search(syscall_pattern, line)

        if not match:
            raise ValueError(f"[PARSER ERROR] Regex unable to identify system call prefix: {line}")

        syscall_name = match.group(1)

        match syscall_name:
            case "socket":
                return self.parse_socket(line, pid)
            
            case "connect" | "bind" | "listen" | "accept" | "accept4":
                return self.parse_connection(syscall_name, line, pid)
                
            case "read" | "write":
                return self.parse_data(syscall_name, line, pid)

            case "execve":
                return self.parse_procexec(line, pid)
                
            case "open" | "openat" | "unlink" | "unlinkat":
                return self.parse_file_access(syscall_name, line, pid)
                
            case "fork" | "clone" | "vfork" | "clone3":
                return self.parse_fork(syscall_name, line, pid)
                
            case "chmod" | "fchmod" | "fchmodat":
                return self.parse_permission(syscall_name, line, pid)

            case "dup" | "dup2" | "dup3":
                return self.parse_fd_dup(syscall_name, line, pid)

            case "setuid" | "setgid" | "setreuid" | "setregid":
                return self.parse_privilege(syscall_name, line, pid)
            
            case "ptrace":
                return self.parse_ptrace(line, pid)

            case "close":
                return self.parse_close(line, pid)
                
            case _:
                raise ValueError(f"[PARSER ERROR] No parser registered for system call: {syscall_name}")


    def parse_socket(self, line: str, pid: int) -> SocketInfo:
        """
        Parse socket operations

        Example: socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
        """
        pattern = r'socket\(([^,]+),\s*([^,]+),\s*([^,]+)\)\s+=\s+(-?\d+)'
        match = re.match(pattern, line)

        if match:
            family, sock_type, protocol, fd = match.groups()

            return SocketInfo(
                operation=SocketOperation.SOCKET,
                domain=SocketDomain(family), 
                type=SocketType(sock_type), 
                protocol=SocketProtocol(protocol), 
                fd=int(fd),
                pid=pid
            )
        
        raise ValueError(f"[SOCKET PARSER ERROR] Regex unable to parse socket info: {line}")


    def parse_connection(self, syscall: str, line: str, pid: int) -> ConnectionInfo:
        """
        Parse connection operations

        Example:
            - connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0
            - bind(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 0
            - listen(3, 128) = 0
            - accept(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 4
            - accept4(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16, SOCK_NONBLOCK) = 4
        """
        match syscall:
            case "connect" | "bind" | "accept":
                pattern = r'[a-z]+\((\d+),\s*\{.+=(.+),\s*.+=.+\((\d+)\),\s*.+=.+\("(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"\)\},\s*(\d+)\)\s*=\s*(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    sockfd, family, port, ip, addrlen, ret_val = match.groups()

                    return ConnectionInfo(
                        operation=ConnectionOperation(syscall),
                        sockfd=int(sockfd), 
                        addr={
                            "sa_family": family,
                            "sin_port": int(port),
                            "sin_addr": ip
                        },
                        addrlen=int(addrlen),
                        ret_val=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[CONNECTION PARSER ERROR] Failed to parse {line}")

            case "listen":
                pattern = r'[a-z]+\((\d+),\s+(\d+)\)\s+=\s(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    sockfd, backlog, ret_val = match.groups()
                    return ConnectionInfo(
                        operation=ConnectionOperation(syscall),
                        sockfd=int(sockfd),
                        backlog=int(backlog),
                        ret_val=int(ret_val),
                        pid=pid
                    )

                raise ValueError(f"[CONNECTION PARSER ERROR] Failed to parse {line}")

            case "accept4":
                pattern = r'[a-z]+\((\d+),\s*\{.+=(.+),\s*.+=.+\((\d+)\),\s*.+=.+\("(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"\)\},\s*(\d+),\s*([A-Z0-9_|]+)\)\s*=\s*(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    sockfd, family, port, ip, addrlen, flags, ret_val = match.groups()
                    return ConnectionInfo(
                        operation=ConnectionOperation(syscall),
                        sockfd=int(sockfd),
                        addr={
                            "sa_family": family,
                            "sin_port": int(port),
                            "sin_addr": ip
                        },
                        addrlen=int(addrlen),
                        flags=flags.split("|"),
                        ret_val=int(ret_val),
                        pid=pid
                    )

                raise ValueError(f"[CONNECTION PARSER ERROR] Failed to parse {line}")

            case _:
                raise ValueError(f"{syscall} not parsable connection system call")

        raise ValueError(f"[CONNECTION PARSER ERROR] Regex unable to parse connection info: {line}")


    def parse_data(self, syscall: str, line: str, pid: int) -> DataTransfer:
        """
        Parse Data Transfer operations

        Examples:  
            - write(3, "Hello World!\n", 13) = 13
            - read(3, "Boo!\n", 2048) = 5
        """
        pattern = r'[a-z]+\((\d+),\s*"([^"]*)",\s*(\d+)\)\s*=\s*(-?\d+)'
        match = re.match(pattern, line)
        
        if match:
            fd, data, bytes_requested, bytes_transferred = match.groups()
            return DataTransfer(
                operation=DataTransferOperation(syscall), 
                fd=int(fd), 
                data=data, 
                bytes_requested=int(bytes_requested), 
                bytes_transferred=int(bytes_transferred),
                pid=pid
            )

        raise ValueError(f"[DATA TRANSFER PARSER ERROR] Regex unable to parse data transfer: {line}")


    def parse_procexec(self, line: str, pid: int) -> ProcessExec:
        """
        Parse Process Exec (Process executing another process)

        Structure examples:
            - execve("/usr/bin/bash", ["/usr/bin/bash"], 0x7fffc2c935f0 /* 152 vars */) = 0
            - execve("/bin/sh", ["sh", "-i"], [/* 24 vars */]) = 0
        """
        pattern = r'execve\("([^"]+)",\s*\[(.*)\],\s*(.*?)\)\s*=\s*(-?\d+)'
        match = re.match(pattern, line)
        
        if match:
            pathname, args_raw, envp_raw, ret_val = match.groups()
            args = [a.strip('"') for a in args_raw.split(", ")] if args_raw else []

            return ProcessExec(
                operation=ProcessExecOperation.EXECVE,
                pathname=pathname,
                args=args,
                envp=envp_raw,
                ret_val=int(ret_val),
                pid=pid
            )
        
        raise ValueError(f"[PROCESS EXEC PARSER ERROR] Regex unable to parse process exec: {line}")


    def parse_file_access(self, syscall: str, line: str, pid: int) -> FileAccess:
        """
        Parse File Access operations

        Examples:
            - open("/etc/passwd", O_RDONLY) = 3
            - openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4
            - unlink("/tmp/payload") = 0
            - unlinkat(AT_FDCWD, "example.txt", 0) = 0
        """
        match syscall:
            case "open":
                pattern = r'[a-z]+\("([^"]+)",\s*([A-Z_|]+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    path, flags, ret_val = match.groups()

                    return FileAccess (
                        operation=FileAccessOperation(syscall),
                        path=path,
                        flags=[flag.strip('"') for flag in flags.split("|")],
                        ret_val=int(ret_val),
                        pid=pid
                    )

                raise ValueError(f"[FILE ACCESS PARSER ERROR] Regex unable to parse file access details: {line}")

            case "unlink":
                pattern = r'[a-z]+\("([^"]+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    path, ret_val = match.groups()

                    return FileAccess(
                        operation=FileAccessOperation(syscall),
                        path=path,
                        ret_val=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[FILE ACCESS PARSER ERROR] Regex unable to parse file access details: {line}")

            case "openat" | "unlinkat":
                pattern = r'[a-z]+\(([^,]+),\s*"([^"]+)",\s*([A-Z_|]+)\)\s*=\s*(-?\d+)'
                match = re.match(pattern, line)
                
                if match:
                    dirfd, path, flags, ret_fd = match.groups()

                    return FileAccess(
                        operation=FileAccessOperation(syscall),
                        dirfd=dirfd,
                        path=path, 
                        flags=[flag.strip('"') for flag in flags.split("|")],
                        ret_val=int(ret_fd),
                        pid=pid
                    )

                raise ValueError(f"[FILE ACCESS PARSER ERROR] Regex unable to parse file access details: {line}")

        raise ValueError(f"[FILE ACCESS PARSER ERROR] Unable to parse file access: {line}")

    
    def parse_fork(self, syscall: str, line: str, pid: int) -> ProcessFork:
        """
        Parse fork/clone system calls

        Example: 
            - 1000  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, ...) = 1001
            - 1000  fork() = 1001
        """
        pattern = r'[a-z0-9]+\(.*\)\s+=\s+(-?\d+)'
        match = re.match(pattern, line)

        if match:
            child_pid = match.group(1)
            return ProcessFork(
                operation=ForkOperation(syscall),
                parent_pid=pid,
                child_pid=int(child_pid),
                pid=pid
            )   

        raise ValueError(f"[FORK/CLONE PARSER ERROR] Unable to parse fork/clone: {line}")


    def parse_close(self, line: str, pid: int) -> SyscallClose:
        """
        Parse close operation

        Example: close(3) = 0
        """
        pattern = r'close\((\d+)\)\s*=\s*(-?\d+)'
        match = re.match(pattern, line)
        
        if match:
            fd, ret_val = match.groups()

            return SyscallClose(
                operation=SyscallCloseOperation.CLOSE,
                fd=int(fd), 
                ret_val=int(ret_val),
                pid=pid
            )

        raise ValueError(f"[CLOSE PARSER ERROR] Regex unable to parse close: {line}")


    def parse_permission(self, syscall: str, line: str, pid: int) -> PermissionInfo:
        """
        Parse permission operation

        Example:
            - chmod("file", 0644) = 0
            - fchmod(3, 0644) = 0
            - fchmodat(AT_FDCWD, "file.txt", 0644) = 0
        """
        match syscall:
            case "chmod":
                pattern = r'[a-z]+\("([^"]+)",\s*(\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    path, mode, ret_val = match.groups()

                    return PermissionInfo(
                        operation=PermissionOperation(syscall),
                        path=path,
                        mode=int(mode, 8),
                        ret_val=int(ret_val),
                        pid=pid
                    )

                raise ValueError(f"[PERMISSION PARSER ERROR] Regex unable to parse chmod: {line}")
            
            case "fchmod":
                pattern = r'[a-z]+\((\d+),\s*(\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    fd, mode, ret_val = match.groups()

                    return PermissionInfo(
                        operation=PermissionOperation(syscall),
                        fd=int(fd),
                        mode=int(mode, 8),
                        ret_val=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[PERMISSION PARSER ERROR] Regex unable to parse fchmod: {line}")
            
            case "fchmodat":
                pattern = r'[a-z]+\(([^,]+),\s*"([^"]+)",\s*(\d+)(?:,\s*([A-Z_|]+))?\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    dirfd, path, mode, flags, ret_val = match.groups()

                    return PermissionInfo(
                        operation=PermissionOperation(syscall),
                        dirfd=dirfd,
                        path=path,
                        mode=int(mode, 8),
                        flags=[flag.strip('"') for flag in flags.split("|")],
                        ret_val=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[PERMISSION PARSER ERROR] Regex unable to parse fchmodat: {line}")
            
        raise ValueError(f"[PERMISSION PARSER ERROR] Regex unable to parse permission: {line}")


    def parse_fd_dup(self, syscall: str, line: str, pid: int) -> FDDuplication:
        """
        Parse fd duplication operation

        Example: 
            - dup(3) = 0
            - dup2(3, 0) = 0
            - dup3(3, 0, O_CLOEXEC) = 0
        """
        match syscall:
            case "dup":
                pattern = r'[a-z0-9]+\((\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    oldfd, ret_val = match.groups()

                    return FDDuplication(
                        operation=FDDuplicationOperation(syscall),
                        oldfd=int(oldfd),
                        ret_value=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[FD DUPLICATION PARSER ERRER] Regex unable to parse dup: {line}")

            case "dup2":
                pattern = r'[a-z0-9]+\((\d+),\s*(\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    oldfd, newfd, ret_val = match.groups()

                    return FDDuplication(
                        operation=FDDuplicationOperation(syscall),
                        oldfd=int(oldfd),
                        newfd=int(newfd),
                        ret_value=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[FD DUPLICATION PARSER ERRER] Regex unable to parse dup2: {line}")

            case "dup3":
                pattern = r'[a-z0-9]+\((\d+),\s*(\d+),\s*([A-Z0-9_|]+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    oldfd, newfd, flags, ret_val = match.groups()

                    return FDDuplication(
                        operation=FDDuplicationOperation(syscall),
                        oldfd=int(oldfd),
                        newfd=int(newfd),
                        flags=[flag.strip('"') for flag in flags.split("|")],
                        ret_value=int(ret_val),
                        pid=pid
                    )
                
                raise ValueError(f"[FD DUPLICATION PARSER ERRER] Regex unable to parse dup3: {line}")

        raise ValueError(f"[FD DUPLICATION PARSER ERRER] Regex unable to parse duplication: {line}")



    def parse_privilege(self, syscall: str, line: str, pid: int) -> PrivilegeInfo:
        """
        Parse privilege operation

        Example: 
            - setuid(0) = 0
            - setgid(0) = 0
            - setreuid(1000, 1000) = 0
            - setregid(1000, 1000) = 0
        """
        match syscall:
            case "setuid" | "setgid":
                pattern = r'[a-z]+\((\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    id, ret_val = match.groups()

                    if syscall == "setuid":
                        return PrivilegeInfo(
                            operation=PrivilegeOperation(syscall),
                            uid=int(id),
                            ret_val=int(ret_val),
                            pid=pid
                        )
                    elif syscall == "setgid":
                        return PrivilegeInfo(
                            operation=PrivilegeOperation(syscall),
                            gid=int(id),
                            ret_val=int(ret_val),
                            pid=pid
                        )
                
                raise ValueError(f"[PRIVILEGE PARSER ERROR] Regex unable to parse setuid/setgid: {line}")
        
            case "setreuid" | "setregid":
                pattern = r'[a-z]+\((-?\d+),\s*(-?\d+)\)\s+=\s+(-?\d+)'
                match = re.match(pattern, line)

                if match:
                    rid, eid, ret_val = match.groups()

                    if syscall == "setreuid":
                        return PrivilegeInfo(
                            operation=PrivilegeOperation(syscall),
                            ruid=int(rid),
                            euid=int(eid),
                            ret_val=int(ret_val),
                            pid=pid
                        )
                    elif syscall == "setregid":
                        return PrivilegeInfo(
                            operation=PrivilegeOperation(syscall),
                            rgid=int(rid),
                            egid=int(eid),
                            ret_val=int(ret_val),
                            pid=pid
                        )
                
                raise ValueError(f"[PRIVILEGE PARSER ERROR] Regex unable to parse setreuid/setregid: {line}")

        raise ValueError(f"[PRIVILEGE PARSER ERROR] Regex unable to parse: {line}")


    def parse_ptrace(self, line: str, pid: int) -> PTraceInfo:
        """
        Parse ptrace operation

        Example: 
            - ptrace(PTRACE_ATTACH, 12345, NULL, NULL) = 0
            - ptrace(PTRACE_PEEKTEXT, 12345, 0x7fffc2c935f0, NULL) = 0xabcdef01
            - ptrace(PTRACE_CONT, 12345, NULL, SIGINT) = 0
            - ptrace(PTRACE_SETREGS, 12345, NULL, 0x7ffd587d60f0) = 0
            - ptrace(PTRACE_POKETEXT, 12345, 0x7fffc2c935f0, 0x12345678) = 0
        """
        pattern = r'ptrace\(([^,]+),\s*(\d+),\s*([^,]+),\s*([^)]+)\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)(?: .*)?'
        match = re.match(pattern, line)

        if match:
            op, t_pid, addr, data, ret_val_str = match.groups()
            
            if ret_val_str.startswith("0x"):
                ret_val = int(ret_val_str, 16)
            else:
                ret_val = int(ret_val_str)

            return PTraceInfo(
                operation=PTraceOperation.PTRACE,
                op=op,
                t_pid=int(t_pid),
                addr=addr if addr != "NULL" else None,
                data=data if data != "NULL" else None,
                ret_val=ret_val,
                pid=int(pid)
            )

        raise ValueError(f"[PTRACE PARSER ERROR] Regex unable to parse ptrace: {line}")