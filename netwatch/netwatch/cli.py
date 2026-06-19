"""
Command-line interface for netwatch.

This module provides the entry point for the netwatch CLI tool, which analyzes strace/dtruss output for network activity.
"""
from typing import Optional
import subprocess
from sys import stderr
from queue import Queue
import threading
import argparse
import shlex
import logging
import time
from .analyzer import analyze_syscall_stream
from .state import SyscallState



logger = logging.getLogger(__name__)


def main():
    """
    Entry point for the netwatch CLI.

    Parses command-line arguments and dispatches to analyzer.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument("process", nargs="?", help="Specify single process to trace")
    parser.add_argument("-v", "--verbose", help="Displays verbose logging to console", action="store_true")
    parser.add_argument("-p", "--pid", nargs="*", help="Specify process id(s) to trace")
    parser.add_argument("-i", "--input", nargs="?", help="Preform analysis on strace log file based on input file")
    # Flags: -o (FILE OUTPUT), -c (SUMMARY), -e (FILTERING), -s (OUTPUT SIZE), -v (VERBOSE), -t (ADDS TIME CLOCK), -tt (ADDS MICROSECONDS), -T (SHOW TOTAL DURATION)
    # Sample input: -a "-e trace=network"
    parser.add_argument("-a", "--args", help="Pass specific strace flags to customize output")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level = logging.INFO if args.verbose else logging.WARNING,
        stream = stderr,
        format = "[%(levelname)s] %(asctime)s - %(name)s: %(message)s",
        datefmt = "%H:%M:%S",
        force = True
    )

    strace_proc = None

    if not args.input:
        if args.process and args.pid:
            logger.warning("[ERROR] Cannot trace both single process and pid(s) at same time. Please run netwatch again and include either process to spawn or -p argument(s)")
            return

        if not args.process and not args.pid:
            logger.warning("[ERROR] No process or pid(s) to trace specified. Please run netwatch again and include -p argument")
            return 
        
        cmd = ["strace", "-f"]
        if args.process:
            cmd.extend([args.process])
        elif args.pid:
            for pid in args.pid:
                if pid.isdigit():
                    cmd.extend(["-p", pid])
        
        if args.args:
            cmd.extend(shlex.split(args.args)) # Sanitize inputs

        # Start strace process
        # !Important: Strace is continuous without stop command. Popen is non-blocking. Read output from specified file
        strace_proc = subprocess.Popen(
            cmd,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

    syscall_queue = Queue()

    producer_thread_event = threading.Event()
    consumer_thread_event = threading.Event()
    
    if args.process or args.pid:
        producer_thread = threading.Thread(target=producer, kwargs={"q": syscall_queue, "event": producer_thread_event, "process": strace_proc}, daemon=True)
    if args.input:
        producer_thread = threading.Thread(target=producer, kwargs={"q": syscall_queue, "event": producer_thread_event, "file": args.input}, daemon=True)

    consumer_thread = threading.Thread(target=consumer, args=(syscall_queue, consumer_thread_event), daemon=True)

    try:
        logger.info("[INFO] Starting Netwatch. Looking for anamolies...")
        producer_thread.start()
        consumer_thread.start()
        producer_thread.join()

        if args.input:
            while not syscall_queue.empty():
                time.sleep(0.5)

            consumer_thread_event.set()

    except KeyboardInterrupt:
        producer_thread_event.set()
        consumer_thread_event.set()

        if strace_proc is not None:
            if not strace_proc.poll():
                strace_proc.kill() # Kill strace subprocess on CTRL + C input

        logger.info("[INFO] Netwatch exited")
        
        
def producer(q: Queue, event: threading.Event, process: Optional[subprocess.Popen[str]] = None, file: Optional[str] = None) -> None:
    """
    Reads lines from syscall stdout and adds line to queue
    """
    if not process and not file:
        logger.warning("[PROGRAM ERROR] Tracee not defined. Nothing to analyze")
        return

    if file:
        try:
            with open(file, "r") as f:
                lines = f.readlines()
                for line in lines:
                    if event.is_set():
                        break
                    q.put(line)
        except FileNotFoundError as e:
            logger.warning("[PROGRAM ERROR] File not found: {e}")

    elif process:
        for line in process.stderr:
            if event.is_set():
                break
            q.put(line)


def consumer(q: Queue, event: threading.Event, state: SyscallState = None) -> None:
    """
    Pass queue to analyzer with event for tracking program state
    """
    analyze_syscall_stream(q, event, state)

if __name__ == "__main__":
    main()