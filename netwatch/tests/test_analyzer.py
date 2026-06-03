from netwatch.parser import SyscallParser
from netwatch.analyzer import SYSCALL_ENTRIES
from netwatch.models import ConnectionInfo
from netwatch.cli import consumer
from queue import Queue
import threading
import time
import pytest



parser = SyscallParser()
syscall_queue= Queue()

consumer_stop_event = threading.Event()

consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event), daemon=True)
consumer_thread.start()

def test_valid_stream():
    line = 'connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
    SYSCALL_ENTRIES.clear()

    syscall_queue.put(line)

    time.sleep(0.1)

    consumer_stop_event.set()

    entry: ConnectionInfo = SYSCALL_ENTRIES[0]
    assert isinstance(entry, ConnectionInfo)
    assert entry.family == "AF_INET"
    assert entry.fd == 3
    assert entry.port == 5555
    assert entry.ip == "192.168.10.1"

def test_invalid_stream():
    line = 'connection(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
    SYSCALL_ENTRIES.clear()

    syscall_queue.put(line)

    time.sleep(0.1)

    consumer_stop_event.set()
    pytest.raises(ValueError, match="No parser method registered for system call")
        