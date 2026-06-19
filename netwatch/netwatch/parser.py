"""
Parse strace output for analyzing
"""

import re
import logging
from typing import Any
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
    PTraceOperation,
    Token
)
from .exceptions import ParserError, LexerError


logger = logging.getLogger(__name__)


class Peekable:
    """A wrapper for iterators that allows looking ahead one token."""
    def __init__(self, iterable):
        self.it = iter(iterable)
        self.peeked = None

    def __str__(self):
        if self.peeked:
            return f"Next item: {self.peeked[0]}"
        return f"Next item: {self.it[0]}"

    def peek(self):
        if self.peeked is None:
            try:
                self.peeked = [next(self.it)]
            except StopIteration:
                self.peeked = []
        return self.peeked[0] if self.peeked else None

    def __next__(self):
        if self.peeked:
            val = self.peeked.pop(0)
            if not self.peeked:
                self.peeked = None
            return val
        return next(self.it)

    def __bool__(self):
        return self.peek() is not None


class BaseParser:
    TOKEN_SPECIFICATIONS: list[tuple[str, str]] = [
        ("HEX", r'0x[0-9a-fA-F]+'),
        ("NUMBER", r'-?\d+'),
        ("STRING", r'"[^"]*"'),
        ("LBRACKET", r'\['),
        ("RBRACKET", r'\]'),
        ("LBRACE", r'\{'),
        ("RBRACE", r'\}'),
        ("LPAREN", r'\('),
        ("RPAREN", r'\)'),
        ("EQUALS", r'='),
        ("COMMA", r','),
        ("COMMENT", r'\/\*.*?\*\/'),           # C-style comments (e.g. /* 24 vars */)
        ("ID", r'[a-zA-Z0-9_|]+'),             # Identifiers, constants, signal names
        ("SKIP", r'[ \t\n]+'),                 # Ignore spaces and tabs
        ("ELLIPSIS", r'\.\.\.'),               # Truncation ellipsis
        ("MISMATCH", r'.')                     # Catch everything else
    ] 

    def tokenize(self, line: str) -> list[Token]:
        """
        Scans text and returns a list of Token objects
        """
        tok_regex = "|".join(f"(?P<{name}>{pattern})" for name, pattern in self.TOKEN_SPECIFICATIONS)
        tokens = []
        for token in re.finditer(tok_regex, line):
            kind = token.lastgroup
            value = token.group()
            if kind == "SKIP":
                continue
            elif kind == "MISMATCH":
                raise LexerError(f"Unexpected token/character: {value!r}")
            
            tokens.append(Token(kind, value))
        
        return tokens

    def parse_value(self, it: Peekable) -> Any:
        """Recursively parses a token stream into native Python structures."""
        token = next(it, None)

        if not token:
            raise ParserError("parser", "Unexpected end of input")
        
        match token.type:
            case "LBRACE":
                d = self._handle_lbrace(it)
                return d

            case "LBRACKET":
                lst = self._handle_lbracket(it)
                return lst
            
            case "ID":
                val = self._handle_id(token, it)
                return val

            case "NUMBER":
                num = self._handle_number(token)
                return num
            
            case "HEX":
                return int(token.value, 16)
            
            case "STRING":
                return token.value[1:-1] # strip double quotes
            
            case "COMMENT":
                return token.value
                
            case "ELLIPSIS":
                return "..."
                
            case _:
                raise ParserError("parser", f"Unexpected token type '{token.type}' with value: {token.value}")

    def _handle_lbrace(self, it: Peekable) -> dict[str, Any]:
        """Parse struct: {key=value, key2=value2, ...}"""
        d = {}
        while True:
            peek_tok = it.peek()
            if not peek_tok or peek_tok.type == "RBRACE":
                break

            if peek_tok.type == "ELLIPSIS":
                next(it)
                d["..."] = "..."
                comma_tok = it.peek()
                if comma_tok and comma_tok.type == "COMMA":
                    next(it)
                continue

            key_tok = next(it)
            if key_tok.type != "ID":
                raise ParserError("parser", f"Expected key identifier in struct, got {key_tok.value}")
            key = key_tok.value
            
            eq_tok = next(it, None)
            if not eq_tok or eq_tok.type != "EQUALS":
                raise ParserError("parser", f"Expected '=' after key '{key}'")
                
            val = self.parse_value(it)
            d[key] = val
            
            comma_tok = it.peek()
            if comma_tok and comma_tok.type == "COMMA":
                next(it)
        
        rbrace = next(it, None)
        if not rbrace or rbrace.type != "RBRACE":
            raise ParserError("parser", "Expected '}' at end of struct")

        return d
            
    def _handle_lbracket(self, it: Peekable) -> list[Any]:
        """Parse list: [value, value2, ...]"""
        lst = []
        while True:
            peek_tok = it.peek()
            if not peek_tok or peek_tok.type == "RBRACKET":
                break
            
            if peek_tok.type == "COMMENT":
                comment_tok = next(it)
                lst.append(comment_tok.value)
            elif peek_tok.type == "ELLIPSIS":
                next(it)
                lst.append("...")
            else:
                val = self.parse_value(it)
                lst.append(val)
            
            comma_tok = it.peek()
            if comma_tok and comma_tok.type == "COMMA":
                next(it)
        
        rbracket = next(it, None)
        if not rbracket or rbracket.type != "RBRACKET":
            raise ParserError("parser", "Expected ']' at end of list")
        return lst

    def _handle_id(self, token: Token, it: Peekable) -> str:
        """Check if this is a function call wrapper (e.g. htons(5555))"""
        peek_token = it.peek()
        if peek_token and peek_token.type == "LPAREN":
            func_name = token.value
            next(it) # consume LPAREN
            
            func_args = []
            while True:
                p_tok = it.peek()
                if not p_tok or p_tok.type == "RPAREN":
                    break

                val = self.parse_value(it)
                func_args.append(val)
                
                comma_tok = it.peek()
                if comma_tok and comma_tok.type == "COMMA":
                    next(it)
            
            rparen = next(it, None)
            if not rparen or rparen.type != "RPAREN":
                raise ParserError("parser", f"Expected ')' at end of function '{func_name}'")
            
            # Semantic unwrapping of standard wrapper functions
            if func_name == "htons" and func_args:
                return func_args[0]
            elif func_name in ("inet_addr", "inet_pton") and func_args:
                return func_args[-1]  # IP string
            else:
                args_str = ", ".join(repr(a) for a in func_args)
                return f"{func_name}({args_str})"
        elif peek_token and peek_token.type == "EQUALS":
            key = token.value
            next(it) # consume EQUALS
            val = self.parse_value(it)
            return f"{key}={val}"
        else:
            return token.value

    def _handle_number(self, token: Token) -> int:
        """Handle octal literals (permission modes like 0644)"""
        if token.value.startswith("0") and len(token.value) > 1:
            try:
                return int(token.value, 8)
            except ValueError:
                pass
        return int(token.value)


class SyscallParser(BaseParser):
    def __init__(self, default_pid: int = 0):
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
            pid = int(re.sub(r'\D', '', pid_str)) # sub anything that is not a digit

        return self._parse_syscall(clean_line, pid)

    def _parse_syscall(self, line: str, pid: int) -> ParserEvent:
        """
        Helper method to route line to proper parser
        """
        try:
            syscall_name, raw_args, ret_val = self._parse_outer_syscall(line)
        except ParserError:
            raise ParserError("parser", f"Failed to identify system call prefix: {line}")

        try:
            tokens = self.tokenize(raw_args)
            args = self._parse_arguments(tokens)
        except LexerError as e:
            raise ParserError("parser", f"Lexer error: {e}")
        except ParserError as e:
            raise ParserError("parser", f"Parser error: {e}")

        match syscall_name:
            case "socket":
                return self._parse_socket(args, ret_val, pid)
            
            case "connect" | "bind" | "listen" | "accept" | "accept4":
                return self._parse_connection(syscall_name, args, ret_val, pid)
                
            case "read" | "write":
                return self._parse_data(syscall_name, args, ret_val, pid)

            case "execve":
                return self._parse_procexec(args, ret_val, pid)
                
            case "open" | "openat" | "unlink" | "unlinkat":
                return self._parse_file_access(syscall_name, args, ret_val, pid)
                
            case "fork" | "clone" | "vfork" | "clone3":
                return self._parse_fork(syscall_name, args, ret_val, pid)
                
            case "chmod" | "fchmod" | "fchmodat":
                return self._parse_permission(syscall_name, args, ret_val, pid)

            case "dup" | "dup2" | "dup3":
                return self._parse_fd_dup(syscall_name, args, ret_val, pid)

            case "setuid" | "setgid" | "setreuid" | "setregid":
                return self._parse_privilege(syscall_name, args, ret_val, pid)
            
            case "ptrace":
                return self._parse_ptrace(args, ret_val, pid)

            case "close":
                return self._parse_close(args, ret_val, pid)
                
            case _:
                raise ParserError("parser", f"No parser registered for system call: {syscall_name}")

    def _parse_outer_syscall(self, line: str) -> tuple[str, str, int]:
        """
        Parses the outer structure of a system call: name(args) = ret_val
        """
        match = re.match(r'^([a-z0-9_]+)\((.*)\)\s*=\s*(-?\d+|0x[0-9a-fA-F]+)(?: .*)?$', line, flags=re.DOTALL)
        if not match:
            raise ParserError("parser", f"Failed to parse outer syscall structure: {line}")
            
        syscall_name = match.group(1)
        raw_args = match.group(2)
        ret_val_str = match.group(3)
        
        if ret_val_str.startswith("0x"):
            ret_val = int(ret_val_str, 16)
        else:
            ret_val = int(ret_val_str)
            
        return syscall_name, raw_args, ret_val

    def _parse_arguments(self, tokens: list[Token]) -> list[Any]:
        """Parses a complete list of comma-separated tokens."""
        it = Peekable(tokens)
        args = []
        while it:
            val = self.parse_value(it)
            args.append(val)
            
            comma_tok = it.peek()
            if comma_tok and comma_tok.type == "COMMA":
                next(it)
        return args

    def _parse_socket(self, args: list[Any], ret_val: int, pid: int) -> SocketInfo:
        """Parse socket operations"""
        if len(args) < 3:
            raise ParserError("socket", f"Missing arguments: expected 3, got {len(args)}")
        
        return SocketInfo(
            operation=SocketOperation.SOCKET,
            domain=SocketDomain(args[0]), 
            type=SocketType(args[1]), 
            protocol=SocketProtocol(args[2]), 
            fd=ret_val,
            pid=pid
        )

    def _parse_connection(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> ConnectionInfo:
        """Parse connection operations"""
        if syscall == "listen":
            if len(args) < 2:
                raise ParserError("connection", f"listen requires 2 arguments, got {len(args)}")
            return ConnectionInfo(
                operation=ConnectionOperation.LISTEN,
                sockfd=args[0],
                backlog=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        if len(args) < 3:
            raise ParserError("connection", f"{syscall} requires at least 3 arguments, got {len(args)}")
            
        addr = args[1]
        addrlen = args[2]
        flags = None
        
        if len(args) > 3 and args[3]:
            if isinstance(args[3], str):
                flags = [f.strip() for f in args[3].split("|")]
                
        return ConnectionInfo(
            operation=ConnectionOperation(syscall),
            sockfd=args[0],
            addr=addr if isinstance(addr, dict) else None,
            addrlen=addrlen,
            flags=flags,
            ret_val=ret_val,
            pid=pid
        )

    def _parse_data(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> DataTransfer:
        """Parse Data Transfer operations"""
        if len(args) < 3:
            raise ParserError("data transfer", f"Missing arguments: expected 3, got {len(args)}")
        return DataTransfer(
            operation=DataTransferOperation(syscall), 
            fd=args[0], 
            data=args[1], 
            bytes_requested=args[2], 
            bytes_transferred=ret_val,
            pid=pid
        )

    def _parse_procexec(self, args: list[Any], ret_val: int, pid: int) -> ProcessExec:
        """Parse Process Exec"""
        if len(args) < 3:
            raise ParserError("process exec", f"Missing arguments: expected 3, got {len(args)}")
            
        raw_args = args[1]
        if isinstance(raw_args, list):
            argv = [str(a) for a in raw_args]
        else:
            argv = [str(raw_args)]
            
        return ProcessExec(
            operation=ProcessExecOperation.EXECVE,
            pathname=args[0],
            args=argv,
            envp=args[2],
            ret_val=ret_val,
            pid=pid
        )

    def _parse_file_access(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> FileAccess:
        """Parse File Access operations"""
        if syscall == "open":
            if len(args) < 2:
                raise ParserError("file access", f"open requires at least 2 arguments, got {len(args)}")
            flags_val = args[1]
            flags = [f.strip() for f in flags_val.split("|")] if isinstance(flags_val, str) else []
            return FileAccess(
                operation=FileAccessOperation.OPEN,
                path=args[0],
                flags=flags,
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "unlink":
            if len(args) < 1:
                raise ParserError("file access", f"unlink requires 1 argument, got {len(args)}")
            return FileAccess(
                operation=FileAccessOperation.UNLINK,
                path=args[0],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "openat":
            if len(args) < 3:
                raise ParserError("file access", f"openat requires at least 3 arguments, got {len(args)}")
            flags_val = args[2]
            flags = [f.strip() for f in flags_val.split("|")] if isinstance(flags_val, str) else []
            return FileAccess(
                operation=FileAccessOperation.OPENAT,
                dirfd=str(args[0]),
                path=args[1],
                flags=flags,
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "unlinkat":
            if len(args) < 3:
                raise ParserError("file access", f"unlinkat requires at least 3 arguments, got {len(args)}")
            flags_val = args[2]
            flags = [f.strip() for f in flags_val.split("|")] if isinstance(flags_val, str) else []
            return FileAccess(
                operation=FileAccessOperation.UNLINKAT,
                dirfd=str(args[0]),
                path=args[1],
                flags=flags,
                ret_val=ret_val,
                pid=pid
            )
            
        raise ParserError("file access", f"Unknown syscall: {syscall}")

    def _parse_fork(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> ProcessFork:
        """Parse fork/clone system calls"""
        return ProcessFork(
            operation=ForkOperation(syscall),
            parent_pid=pid,
            child_pid=ret_val,
            pid=pid
        )

    def _parse_close(self, args: list[Any], ret_val: int, pid: int) -> SyscallClose:
        """Parse close operation"""
        if len(args) < 1:
            raise ParserError("close", f"close requires 1 argument, got {len(args)}")
        return SyscallClose(
            operation=SyscallCloseOperation.CLOSE,
            fd=args[0], 
            ret_val=ret_val,
            pid=pid
        )

    def _parse_permission(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> PermissionInfo:
        """Parse permission operations"""
        if syscall == "chmod":
            if len(args) < 2:
                raise ParserError("permission", f"chmod requires 2 arguments, got {len(args)}")
            return PermissionInfo(
                operation=PermissionOperation.CHMOD,
                path=args[0],
                mode=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "fchmod":
            if len(args) < 2:
                raise ParserError("permission", f"fchmod requires 2 arguments, got {len(args)}")
            return PermissionInfo(
                operation=PermissionOperation.FCHMOD,
                fd=args[0],
                mode=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "fchmodat":
            if len(args) < 3:
                raise ParserError("permission", f"fchmodat requires at least 3 arguments, got {len(args)}")
            flags_val = args[3] if len(args) > 3 else None
            flags = [f.strip() for f in flags_val.split("|")] if isinstance(flags_val, str) else []
            return PermissionInfo(
                operation=PermissionOperation.FCHMODAT,
                dirfd=str(args[0]),
                path=args[1],
                mode=args[2],
                flags=flags,
                ret_val=ret_val,
                pid=pid
            )
            
        raise ParserError("permission", f"Unknown syscall: {syscall}")

    def _parse_fd_dup(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> FDDuplication:
        """Parse fd duplication operations"""
        if syscall == "dup":
            if len(args) < 1:
                raise ParserError("fd duplication", f"dup requires 1 argument, got {len(args)}")
            return FDDuplication(
                operation=FDDuplicationOperation.DUP,
                oldfd=args[0],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "dup2":
            if len(args) < 2:
                raise ParserError("fd duplication", f"dup2 requires 2 arguments, got {len(args)}")
            return FDDuplication(
                operation=FDDuplicationOperation.DUP2,
                oldfd=args[0],
                newfd=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "dup3":
            if len(args) < 3:
                raise ParserError("fd duplication", f"dup3 requires 3 arguments, got {len(args)}")
            flags_val = args[2]
            flags = [f.strip() for f in flags_val.split("|")] if isinstance(flags_val, str) else []
            return FDDuplication(
                operation=FDDuplicationOperation.DUP3,
                oldfd=args[0],
                newfd=args[1],
                flags=flags,
                ret_val=ret_val,
                pid=pid
            )
            
        raise ParserError("fd duplication", f"Unknown syscall: {syscall}")

    def _parse_privilege(self, syscall: str, args: list[Any], ret_val: int, pid: int) -> PrivilegeInfo:
        """Parse privilege operations"""
        if syscall == "setuid":
            if len(args) < 1:
                raise ParserError("privilege", f"setuid requires 1 argument, got {len(args)}")
            return PrivilegeInfo(
                operation=PrivilegeOperation.SETUID,
                uid=args[0],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "setgid":
            if len(args) < 1:
                raise ParserError("privilege", f"setgid requires 1 argument, got {len(args)}")
            return PrivilegeInfo(
                operation=PrivilegeOperation.SETGID,
                gid=args[0],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "setreuid":
            if len(args) < 2:
                raise ParserError("privilege", f"setreuid requires 2 arguments, got {len(args)}")
            return PrivilegeInfo(
                operation=PrivilegeOperation.SETREUID,
                ruid=args[0],
                euid=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        elif syscall == "setregid":
            if len(args) < 2:
                raise ParserError("privilege", f"setregid requires 2 arguments, got {len(args)}")
            return PrivilegeInfo(
                operation=PrivilegeOperation.SETREGID,
                rgid=args[0],
                egid=args[1],
                ret_val=ret_val,
                pid=pid
            )
            
        raise ParserError("privilege", f"Unknown syscall: {syscall}")

    def _parse_ptrace(self, args: list[Any], ret_val: int, pid: int) -> PTraceInfo:
        """Parse ptrace operations"""
        if len(args) < 4:
            raise ParserError("ptrace", f"ptrace requires 4 arguments, got {len(args)}")
        return PTraceInfo(
            operation=PTraceOperation.PTRACE,
            op=args[0],
            t_pid=args[1],
            addr=str(args[2]) if args[2] != "NULL" else None,
            data=str(args[3]) if args[3] != "NULL" else None,
            ret_val=ret_val,
            pid=pid
        )
