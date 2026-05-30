"""
Command-line interface for netwatch.

This module provides the entry point for the netwatch CLI tool, which analyzes strace/dtruss output for network activity.
"""

from sys import stderr
import argparse
from .analyzer import analyze_syscall_stream
import subprocess
import shlex
import logging



def main():
    """
    Entry point for the netwatch CLI.

    Parses command-line arguments and dispatches to the appropriate handler.
    """
    # Init parser
    parser = argparse.ArgumentParser()

    # Add argments to parser
    parser.add_argument("-v", "--verbose", help="Displays verbose logging to console", action="store_true") # args without action require CLI input. Action specifies what should happen if arg is passed in CLI
    parser.add_argument("-p", "--process", help="Specify process to trace")
    parser.add_argument("-f", "--file", help="Specify file name for raw strace output")

    # Flags: -p (PID), -f (FORK), -o (FILE OUTPUT), -c (SUMMARY), -e (FILTERING), -s (OUTPUT SIZE), -v (VERBOSE), -t (ADDS TIME CLOCK), -tt (ADDS MICROSECONDS), -T (SHOW TOTAL DURATION)
    # Sample input: -a "-f -e trace=network"
    parser.add_argument("-a", "--args", help="Pass specific strace flags to customize output")
    
    # Parse passed args
    args = parser.parse_args() # Creates --help and usage information

    #Create functionality for passed args
    if args.verbose:
        log_level = logging.INFO # CLI input test script (Remove later). Switch to operation the sets setting to detailed logging
    else:
        log_level = logging.WARNING
    
    logging.basicConfig(
        level = log_level,
        stream = stderr,
        format = "[%(levelname)s] %(asctime)s - %(name)s: %(message)s",
        datefmt = "%H:%M:%S",
        force = True
    )

    logger = logging.getLogger(__name__)

    # Catch inputs that don't input process to watch
    if not args.process:
        logger.warning("[ERROR] No process to trace specified. Please run netwatch again and include -p argument")
        return 
    
    # Sanatize CLI inputs
    process = shlex.quote(args.process)
    file = shlex.quote(args.file) if args.file else "default_netwatch_output.log"
    strace_args = [shlex.quote(arg) for arg in args.args.split(" ")] if args.args else []

    # Start strace process
    # !Important: Strace is continuous without stop command. Popen is non-blocking. Read output from specified file
    strace_proc = subprocess.Popen(
        ["strace", "-p", process, "-o", file, *strace_args] if process.isdigit() else ["strace", "-o", file, *strace_args, process], # Add extra args once we decide how we want to handle strace flags. Ex: -o or --output for file output
        text=True
    ) 

    try:
        # Pass filename to main analyzer entry point to start tailing strace logs
        analyze_syscall_stream(file)
    except KeyboardInterrupt:
        if not strace_proc.poll():
            strace_proc.kill() # Kill strace subprocess on CTRL + C input

if __name__ == "__main__":
    main()