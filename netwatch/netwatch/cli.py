"""
Command-line interface for netwatch.

This module provides the entry point for the netwatch CLI tool, which analyzes strace/dtruss output for network activity.
"""

import subprocess
from sys import stderr
from queue import Queue
import threading
import argparse
from .analyzer import analyze_syscall_stream
import shlex
import logging



def main():
    """
    Entry point for the netwatch CLI.

    Parses command-line arguments and dispatches to the appropriate handler.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("-v", "--verbose", help="Displays verbose logging to console", action="store_true")
    
    # !Important: Netwatch monitors processes already running. Requires pids to work
    parser.add_argument("-p", "--pid", nargs="+", help="Specify process id(s) to trace")

    # Flags: -f (FORK), -o (FILE OUTPUT), -c (SUMMARY), -e (FILTERING), -s (OUTPUT SIZE), -v (VERBOSE), -t (ADDS TIME CLOCK), -tt (ADDS MICROSECONDS), -T (SHOW TOTAL DURATION)
    # Sample input: -a "-f -e trace=network"
    parser.add_argument("-a", "--args", help="Pass specific strace flags to customize output")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level = logging.INFO if args.verbose else logging.WARNING,
        stream = stderr,
        format = "[%(levelname)s] %(asctime)s - %(name)s: %(message)s",
        datefmt = "%H:%M:%S",
        force = True
    )

    logger = logging.getLogger(__name__)

    if not args.pid:
        logger.warning("[ERROR] No process id(s) to trace specified. Please run netwatch again and include -p argument")
        return 
    
    # Sanatize CLI inputs
    processes = [pid for pid in args.pid if pid.isdigit()]
    # file = shlex.quote(args.file) if args.file else "default_netwatch_output.log"
    strace_args = shlex.split(args.args)if args.args else []

    # Start strace process
    # !Important: Strace is continuous without stop command. Popen is non-blocking. Read output from specified file
    strace_proc = subprocess.Popen(
        ["strace", "-p", ",".join(processes), "-f", *strace_args], # Add extra args once we decide how we want to handle strace flags. Ex: -o or --output for file output
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    syscall_queue = Queue()

    producer_thread_event = threading.Event()
    consumer_thread_event = threading.Event()
    
    producer_thread = threading.Thread(target=producer, args=(syscall_queue, strace_proc, producer_thread_event), daemon=True)
    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_thread_event), daemon=True)

    try:
        producer_thread.start()
        consumer_thread.start()
        producer_thread.join()
    except KeyboardInterrupt:
        producer_thread_event.set()
        consumer_thread_event.set()
        if not strace_proc.poll():
            strace_proc.kill() # Kill strace subprocess on CTRL + C input

def producer(q: Queue, process: subprocess.Popen[str], event: threading.Event) -> None:
    """
    Reads lines from syscall stdout and adds line to queue
    """
    for line in process.stderr:
        if event.is_set():
            break
        q.put(line)  # Add line to que

def consumer(q: Queue, event: threading.Event) -> None:
    # Pass filename to main analyzer entry point to start tailing strace logs
    analyze_syscall_stream(q, event)

if __name__ == "__main__":
    main()