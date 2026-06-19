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


def test_metrics_accumulation():
    state = SyscallState()
    syscall_queue = Queue()

    # 1. Process Exec
    syscall_queue.put('[pid 1000] execve("/usr/bin/python3", ["python3"], 0x7fffc2c935f0) = 0')
    
    # 2. Socket creation and connection
    syscall_queue.put('[pid 1000] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3')
    syscall_queue.put('[pid 1000] connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("1.2.3.4")}, 16) = 0')
    
    # 3. Socket I/O
    syscall_queue.put('[pid 1000] write(3, "request_payload", 15) = 15')
    syscall_queue.put('[pid 1000] read(3, "response_payload_20", 20) = 20')
    
    # 4. Normal File I/O (fd 4)
    syscall_queue.put('[pid 1000] openat(AT_FDCWD, "/tmp/test.txt", O_WRONLY|O_CREAT) = 4')
    syscall_queue.put('[pid 1000] write(4, "hello_world_file", 16) = 16')
    
    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, state), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    # Assert execution counts
    assert state.process_execution_counts.get("/usr/bin/python3") == 1

    # Assert connection volumes
    net_key = ("1.2.3.4", 8080)
    assert net_key in state.network_destination
    assert state.network_destination[net_key].bytes_sent == 15
    assert state.network_destination[net_key].bytes_received == 20

    # Assert file I/O volumes
    assert state.io_volume[1000].bytes_written == 16
    assert state.io_volume[1000].bytes_read == 0


def test_fsm_backdoor_detection(caplog):
    import logging
    state = SyscallState()
    syscall_queue = Queue()

    # Backdoor sequence
    lines = [
        '[pid 1000] socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3',
        '[pid 1000] bind(3, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, 16) = 0',
        '[pid 1000] listen(3, 128) = 0',
        '[pid 1000] accept(3, {sa_family=AF_INET, sin_port=htons(55555), sin_addr=inet_addr("192.168.1.100")}, 16) = 4',
        '[pid 1000] dup2(4, 0) = 0',
        '[pid 1000] dup2(4, 1) = 1',
        '[pid 1000] dup2(4, 2) = 2',
        '[pid 1000] execve("/bin/sh", ["sh"], 0x7fffc2c935f0) = 0'
    ]

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, state), daemon=True)
    
    with caplog.at_level(logging.WARNING):
        consumer_thread.start()
        time.sleep(0.1)
        consumer_stop_event.set()

    # Check alert was triggered and logged
    assert any("Inbound Backdoor Listener" in record.message for record in caplog.records)
    assert any("CRITICAL" in record.message for record in caplog.records)


def test_fsm_dropper_detection(caplog):
    import logging
    state = SyscallState()
    syscall_queue = Queue()

    # Dropper sequence
    lines = [
        '[pid 2000] openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 3',
        '[pid 2000] write(3, "malicious_bytes", 15) = 15',
        '[pid 2000] fchmod(3, 0755) = 0',
        '[pid 2000] execve("/tmp/payload", ["payload"], 0x7fffc2c935f0) = 0'
    ]

    for line in lines:
        syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event, state), daemon=True)

    with caplog.at_level(logging.WARNING):
        consumer_thread.start()
        time.sleep(0.1)
        consumer_stop_event.set()

    # Check alert was triggered and logged
    assert any("Payload Dropper" in record.message for record in caplog.records)
    assert any("HIGH" in record.message for record in caplog.records)
