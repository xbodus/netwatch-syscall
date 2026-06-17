from netwatch.parser import SyscallParser
from netwatch.models import (
    SocketInfo, 
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
    ProcessExecOperation, 
    FileAccessOperation, 
    SyscallCloseOperation,
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
from netwatch.exceptions import ParserError
import pytest


parser = SyscallParser()


def test_invalid_parse_line():
    with pytest.raises(ParserError):
        line = 'connection(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
        parser.parse_line(line)


def test_parse_socket():
    """
    Test parse_socket correctly parses a socket syscall line
    """
    line = '[pid 1000] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3'
    result = parser.parse_line(line)

    assert isinstance(result, SocketInfo)
    assert result.domain == SocketDomain.PF_INET
    assert result.type == SocketType.SOCK_STREAM
    assert result.protocol == SocketProtocol.IPPROTO_TCP
    assert result.fd == 3


def test_parse_connection():
    """
    Test parse_connection correctly parses a connection syscall line
    """

    lines = [
        'connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0',
        '[pid 1000] bind(4, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 0',
        'listen(3, 128) = 0',
        'accept(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16) = 4',
        '1001 accept4(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("60.10.15.1")}, 16, SOCK_NONBLOCK) = 4'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 5

    connect_result = results[0]
    bind_result = results[1]
    listen_result = results[2]
    accept_result = results[3]
    accept4_result = results[4]

    assert all([isinstance(r, ConnectionInfo) for r in results])

    # Test connect
    assert connect_result.operation == ConnectionOperation.CONNECT
    assert connect_result.sockfd == 3
    assert connect_result.addr["sa_family"] == "AF_INET"
    assert connect_result.addr["sin_port"] == 5555
    assert connect_result.addr["sin_addr"] == "192.168.10.1"
    assert connect_result.addrlen == 16
    assert connect_result.ret_val == 0
    assert connect_result.flags == None
    assert connect_result.backlog == None
    assert connect_result.pid == 0

    # Test bind
    assert bind_result.operation == ConnectionOperation.BIND
    assert bind_result.sockfd == 4
    assert bind_result.addr["sa_family"] == "AF_INET"
    assert bind_result.addr["sin_port"] == 4444
    assert bind_result.addr["sin_addr"] == "60.10.15.1"
    assert bind_result.addrlen == 16
    assert bind_result.ret_val == 0
    assert bind_result.flags == None
    assert bind_result.backlog == None
    assert bind_result.pid == 1000

    # Test listen
    assert listen_result.operation == ConnectionOperation.LISTEN
    assert listen_result.sockfd == 3
    assert listen_result.backlog == 128
    assert listen_result.ret_val == 0
    assert listen_result.addr == None
    assert listen_result.addrlen == None
    assert listen_result.flags == None
    assert listen_result.pid == 0

    # Test accept
    assert accept_result.operation == ConnectionOperation.ACCEPT
    assert accept_result.sockfd == 3
    assert accept_result.backlog == None
    assert accept_result.ret_val == 4
    assert accept_result.addr["sa_family"] == "AF_INET"
    assert accept_result.addr["sin_port"] == 4444
    assert accept_result.addr["sin_addr"] == "60.10.15.1"
    assert accept_result.addrlen == 16
    assert accept_result.flags == None
    assert accept_result.pid == 0

    # Test accept4
    assert accept4_result.operation == ConnectionOperation.ACCEPT4
    assert accept4_result.sockfd == 3
    assert accept4_result.backlog == None
    assert accept4_result.ret_val == 4
    assert accept4_result.addr["sa_family"] == "AF_INET"
    assert accept4_result.addr["sin_port"] == 4444
    assert accept4_result.addr["sin_addr"] == "60.10.15.1"
    assert accept4_result.addrlen == 16
    assert accept4_result.flags == ["SOCK_NONBLOCK"]
    assert accept4_result.pid == 1001


def test_parse_data_transfer():
    """
    Test parse_data correctly parses data transfer syscall line
    """
    lines = [
        'write(3, "Hello World!\n", 13) = 13',
        'read(3, "Boo!\n", 2048) = 5'

    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 2

    write_result = results[0]
    read_result = results [1]

    assert all([isinstance(r, DataTransfer) for r in results])

    # Test write
    assert write_result.operation == DataTransferOperation.WRITE
    assert write_result.fd == 3
    assert write_result.data == "Hello World!\n"
    assert write_result.bytes_requested == 13
    assert write_result.bytes_transferred == 13

    # Test read
    assert read_result.operation == DataTransferOperation.READ
    assert read_result.fd == 3
    assert read_result.data == "Boo!\n"
    assert read_result.bytes_requested == 2048
    assert read_result.bytes_transferred == 5


def test_parse_valid_procexec():
    """
    Test parse_procexec correctly parses a process execution syscall line
    """
    line = 'execve("/usr/bin/bash", ["/usr/bin/bash", "-i"], [/* 24 vars */]) = 0'

    result = parser.parse_line(line)

    assert isinstance(result, ProcessExec)
    assert result.operation == ProcessExecOperation.EXECVE
    assert result.pathname == "/usr/bin/bash"
    assert result.args == ["/usr/bin/bash", "-i"]
    assert result.envp == ["/* 24 vars */"]
    assert result.ret_val == 0


def test_parse_valid_file_access():
    """
    Test parse_file_access correctly parses a file access syscall line
    """
    lines = [
        'open("/etc/passwd", O_RDONLY) = 3',
        'openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4',
        'unlink("/tmp/payload") = 0',
        'unlinkat(AT_FDCWD, "example.txt", 0) = 0'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 4

    open_result = results[0]
    openat_result = results[1]
    unlink_result = results[2]
    unlinkat_result = results[3]

    assert all([isinstance(r, FileAccess) for r in results])

    # Test open
    assert open_result.operation == FileAccessOperation.OPEN
    assert open_result.path == "/etc/passwd"
    assert open_result.flags == ["O_RDONLY"]
    assert open_result.ret_val == 3
    assert open_result.dirfd is None
    assert open_result.pid == 0

    # Test openat
    assert openat_result.operation == FileAccessOperation.OPENAT
    assert openat_result.dirfd == "AT_FDCWD"
    assert openat_result.path == "/tmp/payload"
    assert openat_result.flags == ["O_WRONLY", "O_CREAT"]
    assert openat_result.ret_val == 4
    assert openat_result.pid == 0

    # Test unlink
    assert unlink_result.operation == FileAccessOperation.UNLINK
    assert unlink_result.dirfd is None
    assert unlink_result.path == "/tmp/payload"
    assert unlink_result.flags is None
    assert unlink_result.ret_val == 0
    assert unlink_result.pid == 0

    # Test unlinkat
    assert unlinkat_result.operation == FileAccessOperation.UNLINKAT
    assert unlinkat_result.dirfd == "AT_FDCWD"
    assert unlinkat_result.path == "example.txt"
    assert unlinkat_result.flags == []
    assert unlinkat_result.ret_val == 0
    assert unlinkat_result.pid == 0


def test_parse_close():
    """
    Test parse_close correctly parses a close syscall line
    """
    line = 'close(3) = 0'
    result = parser.parse_line(line)

    assert isinstance(result, SyscallClose)
    assert result.operation == SyscallCloseOperation.CLOSE
    assert result.fd == 3
    assert result.ret_val == 0

def test_parse_fork():
    """
    Test parse_fork correctly parses fork, vfork, clone, clone3 syscall lines
    """
    lines = [
        'fork() = 1001',
        '[pid 1000] vfork() = 1002',
        'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 1003',
        '[pid 1000] clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD}, 88) = 1004'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 4

    fork_res = results[0]
    vfork_res = results[1]
    clone_res = results[2]
    clone3_res = results[3]

    assert all(isinstance(r, ProcessFork) for r in results)

    # fork test
    assert fork_res.operation == ForkOperation.FORK
    assert fork_res.parent_pid == 0
    assert fork_res.child_pid == 1001
    assert fork_res.pid == 0

    # vfork test
    assert vfork_res.operation == ForkOperation.VFORK
    assert vfork_res.parent_pid == 1000
    assert vfork_res.child_pid == 1002
    assert vfork_res.pid == 1000

    # clone test
    assert clone_res.operation == ForkOperation.CLONE
    assert clone_res.parent_pid == 0
    assert clone_res.child_pid == 1003
    assert clone_res.pid == 0

    # clone3 test
    assert clone3_res.operation == ForkOperation.CLONE3
    assert clone3_res.parent_pid == 1000
    assert clone3_res.child_pid == 1004
    assert clone3_res.pid == 1000


def test_parse_permission():
    """
    Test parse_permission correctly parses chmod, fchmod, fchmodat syscall lines
    """
    lines = [
        'chmod("/etc/passwd", 0644) = 0',
        '[pid 1000] fchmod(3, 0644) = 0',
        'fchmodat(AT_FDCWD, "example.txt", 0644, AT_SYMLINK_NOFOLLOW) = 0'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 3

    chmod_res = results[0]
    fchmod_res = results[1]
    fchmodat_res = results[2]

    assert all(isinstance(r, PermissionInfo) for r in results)

    # chmod test
    assert chmod_res.operation == PermissionOperation.CHMOD
    assert chmod_res.path == "/etc/passwd"
    assert chmod_res.mode == 0o644
    assert chmod_res.ret_val == 0
    assert chmod_res.pid == 0

    # fchmod test
    assert fchmod_res.operation == PermissionOperation.FCHMOD
    assert fchmod_res.fd == 3
    assert fchmod_res.mode == 0o644
    assert fchmod_res.ret_val == 0
    assert fchmod_res.pid == 1000

    # fchmodat test
    assert fchmodat_res.operation == PermissionOperation.FCHMODAT
    assert fchmodat_res.dirfd == "AT_FDCWD"
    assert fchmodat_res.path == "example.txt"
    assert fchmodat_res.mode == 0o644
    assert fchmodat_res.flags == ["AT_SYMLINK_NOFOLLOW"]
    assert fchmodat_res.ret_val == 0
    assert fchmodat_res.pid == 0


def test_parse_fd_dup():
    """
    Test parse_fd_dup correctly parses dup, dup2, dup3 syscall lines
    """
    lines = [
        'dup(3) = 4',
        '[pid 1000] dup2(3, 5) = 5',
        'dup3(3, 5, O_CLOEXEC) = 5'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 3

    dup_res = results[0]
    dup2_res = results[1]
    dup3_res = results[2]

    assert all(isinstance(r, FDDuplication) for r in results)

    # dup test
    assert dup_res.operation == FDDuplicationOperation.DUP
    assert dup_res.oldfd == 3
    assert dup_res.ret_value == 4
    assert dup_res.pid == 0

    # dup2 test
    assert dup2_res.operation == FDDuplicationOperation.DUP2
    assert dup2_res.oldfd == 3
    assert dup2_res.newfd == 5
    assert dup2_res.ret_value == 5
    assert dup2_res.pid == 1000

    # dup3 test
    assert dup3_res.operation == FDDuplicationOperation.DUP3
    assert dup3_res.oldfd == 3
    assert dup3_res.newfd == 5
    assert dup3_res.flags == ["O_CLOEXEC"]
    assert dup3_res.ret_value == 5
    assert dup3_res.pid == 0


def test_parse_privilege():
    """
    Test parse_privilege correctly parses setuid, setgid, setreuid, setregid syscall lines
    """
    lines = [
        'setuid(1000) = 0',
        '[pid 1000] setgid(1000) = 0',
        'setreuid(1000, 2000) = 0',
        '[pid 1000] setregid(1000, 2000) = 0'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 4

    setuid_res = results[0]
    setgid_res = results[1]
    setreuid_res = results[2]
    setregid_res = results[3]

    assert all(isinstance(r, PrivilegeInfo) for r in results)

    # setuid test
    assert setuid_res.operation == PrivilegeOperation.SETUID
    assert setuid_res.uid == 1000
    assert setuid_res.ret_val == 0
    assert setuid_res.pid == 0

    # setgid test
    assert setgid_res.operation == PrivilegeOperation.SETGID
    assert setgid_res.gid == 1000
    assert setgid_res.ret_val == 0
    assert setgid_res.pid == 1000

    # setreuid test
    assert setreuid_res.operation == PrivilegeOperation.SETREUID
    assert setreuid_res.ruid == 1000
    assert setreuid_res.euid == 2000
    assert setreuid_res.ret_val == 0
    assert setreuid_res.pid == 0

    # setregid test
    assert setregid_res.operation == PrivilegeOperation.SETREGID
    assert setregid_res.rgid == 1000
    assert setregid_res.egid == 2000
    assert setregid_res.ret_val == 0
    assert setregid_res.pid == 1000


def test_parse_ptrace():
    """
    Test parse_ptrace correctly parses ptrace syscall lines
    """
    lines = [
        'ptrace(PTRACE_ATTACH, 12345, NULL, NULL) = 0',
        '[pid 1000] ptrace(PTRACE_PEEKTEXT, 12345, 0x7fffc2c935f0, NULL) = 0xabcdef01',
        'ptrace(PTRACE_POKETEXT, 12345, 0x7fffc2c935f0, 0x12345678) = 0'
    ]

    results = []
    for line in lines:
        results.append(parser.parse_line(line))

    assert len(results) == 3

    attach_res = results[0]
    peek_res = results[1]
    poke_res = results[2]

    assert all(isinstance(r, PTraceInfo) for r in results)

    # attach test
    assert attach_res.operation == PTraceOperation.PTRACE
    assert attach_res.op == "PTRACE_ATTACH"
    assert attach_res.t_pid == 12345
    assert attach_res.addr is None
    assert attach_res.data is None
    assert attach_res.ret_val == 0
    assert attach_res.pid == 0

    # peek test
    assert peek_res.operation == PTraceOperation.PTRACE
    assert peek_res.op == "PTRACE_PEEKTEXT"
    assert peek_res.t_pid == 12345
    assert peek_res.addr == str(0x7fffc2c935f0)
    assert peek_res.data is None
    assert peek_res.ret_val == 0xabcdef01
    assert peek_res.pid == 1000

    # poke test
    assert poke_res.operation == PTraceOperation.PTRACE
    assert poke_res.op == "PTRACE_POKETEXT"
    assert poke_res.t_pid == 12345
    assert poke_res.addr == str(0x7fffc2c935f0)
    assert poke_res.data == str(0x12345678)
    assert poke_res.ret_val == 0
    assert poke_res.pid == 0
