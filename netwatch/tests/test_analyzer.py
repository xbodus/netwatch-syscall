from netwatch.models import (
    ConnectionInfo, 
    SocketInfo,
    SocketDomain,
    SocketType,
    SocketProtocol, 
    DataTransfer, 
    DataTransferOperation,
    ProcessDetails, 
    FileAccess, 
    FileAccessOperation,
)
from netwatch.cli import consumer
from queue import Queue
import threading
import time
import pytest
from netwatch.state import SyscallState



STATE = SyscallState()


def test_valid_stream_pid_variations():
    syscall_queue = Queue()

    lines = ["socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3", "1000 socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3", "[1001] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3", "[pid 1002] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3"]
    STATE.active_fds.clear()
    STATE.processes.clear()

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    pids = [pid for pid in STATE.active_fds.keys()]

    assert pids[0] == 0
    assert pids[1] == 1000
    assert pids[2] == 1001
    assert pids[3] == 1002

def test_valid_socket_stream():
    syscall_queue = Queue()

    line = "[pid 1000] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3"
    STATE.active_fds.clear()
    STATE.processes.clear()

    syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    pid, entry = list(STATE.active_fds.items())[0]
    assert pid == 1000

    fd, details = list(entry.items())[0]
    assert isinstance(details, SocketInfo)
    assert fd == 3
    assert details.domain == SocketDomain.PF_INET
    assert details.type == SocketType.SOCK_STREAM
    assert details.protocol == SocketProtocol.IPPROTO_TCP

def test_valid_connect_stream():
    syscall_queue= Queue()

    line = '[pid 1000] connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
    STATE.active_fds.clear()
    STATE.processes.clear()

    syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    entry: dict[int, ConnectionInfo] = STATE.active_fds[1000]
    fd, details = list(entry.items())[0]
    assert isinstance(details, ConnectionInfo)
    assert fd == 3
    assert details.addr["sa_family"] == "AF_INET"
    assert details.addr["sin_port"] == 5555
    assert details.addr["sin_addr"] == "192.168.10.1"
    assert details.addrlen == 16
    assert details.ret_val == 0

def test_valid_data_transfer():
    syscall_queue = Queue()

    lines = ['[pid 1000] write(3, "Hello World!\n", 13) = 13', '[pid 1000] read(4, "Boo!\n", 2048) = 5']
    STATE.active_fds.clear()
    STATE.processes.clear()

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    entries: list[int, DataTransfer] = list(STATE.active_fds[1000].items())

    write_fd, write_entry = entries[0]
    read_fd, read_entry = entries[1]

    # Test write
    assert isinstance(write_entry, DataTransfer)
    assert write_fd == 3
    assert write_entry.operation == DataTransferOperation.WRITE
    assert write_entry.data == "Hello World!\n"
    assert write_entry.bytes_requested == 13
    assert write_entry.bytes_transferred == 13

    # Test read
    assert isinstance(read_entry, DataTransfer)
    assert read_fd == 4
    assert read_entry.operation == DataTransferOperation.READ
    assert read_entry.data == "Boo!\n"
    assert read_entry.bytes_requested == 2048
    assert read_entry.bytes_transferred == 5

def test_valid_process_exec():
    syscall_queue = Queue()

    line = '[pid 1000] execve("/usr/bin/bash", ["/usr/bin/bash"], 0x7fffc2c935f0 /* 152 vars */) = 0'
    STATE.active_fds.clear()
    STATE.processes.clear()

    syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    pid, entry = list(STATE.processes.items())[0]

    assert isinstance(entry, ProcessDetails)
    assert pid == 1000
    assert entry.binary_path == "/usr/bin/bash"
    assert entry.parent_pid == None
    assert entry.child_pids == []

def test_valid_file_access():
    syscall_queue = Queue()

    lines = ['[pid 1000] open("/etc/passwd", O_RDONLY) = 3', '[pid 1000] openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4']
    STATE.active_fds.clear()
    STATE.processes.clear()

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    entries: list[int, FileAccess] = list(STATE.active_fds[1000].items())

    open_fd, open_entry = entries[0]
    openat_fd, openat_entry = entries[1]

    # Test open
    assert isinstance(open_entry, FileAccess)
    assert open_entry.ret_val == 3
    assert open_entry.operation == FileAccessOperation.OPEN
    assert open_entry.dirfd == None
    assert open_entry.path == "/etc/passwd"
    assert open_entry.flags == ["O_RDONLY"]

    # Test openat
    assert isinstance(openat_entry, FileAccess)
    assert openat_entry.ret_val == 4
    assert openat_entry.operation == FileAccessOperation.OPENAT
    assert openat_entry.dirfd == "AT_FDCWD"
    assert openat_entry.path == "/tmp/payload"
    assert openat_entry.flags == ["O_WRONLY", "O_CREAT"]

def test_valid_close():
    syscall_queue = Queue()

    line = '[pid 1000] close(3) = 0'
    STATE.active_fds.clear()
    STATE.processes.clear()

    syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    pid, entry = list(STATE.active_fds.items())[0]

    assert pid == 1000
    assert entry == {}

def test_valid_fork():
    syscall_queue = Queue()

    lines = ['[pid 1000] fork() = 1001', '[pid 1000] clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, ...) = 1001']
    STATE.active_fds.clear()
    STATE.processes.clear()

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, STATE), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    pid, entries = list(STATE.processes.items())[0]

    assert isinstance(entries, ProcessDetails)
    assert pid == 1000
    assert entries.binary_path == "Unknown"
    assert entries.parent_pid == None
    assert entries.child_pids == [1001, 1001]