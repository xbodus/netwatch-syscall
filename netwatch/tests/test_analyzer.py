from netwatch.models import ConnectionInfo
from netwatch.cli import consumer
from queue import Queue
import threading
import time
import pytest



SYSCALL_ENTRIES = []

def test_valid_stream():
    syscall_queue= Queue()

    line = 'connect(3, {sa_family=AF_INET, sin_port=htons(5555), sin_addr=inet_addr("192.168.10.1")}, 16) = 0'
    SYSCALL_ENTRIES.clear()

    syscall_queue.put(line)

    consumer_stop_event = threading.Event()
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_stop_event), daemon=True)
    consumer_thread.start()
    time.sleep(0.1)
    consumer_stop_event.set()

    entry: ConnectionInfo = SYSCALL_ENTRIES[0]
    assert isinstance(entry, ConnectionInfo)
    assert entry.family == "AF_INET"
    assert entry.fd == 3
    assert entry.port == 5555
    assert entry.ip == "192.168.10.1"