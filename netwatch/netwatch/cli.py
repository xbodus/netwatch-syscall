"""
Command-line interface for netwatch.

This module provides the entry point for the netwatch CLI tool, which analyzes strace/dtruss output for network activity.
"""

import argparse



def main():
    """
    Entry point for the netwatch CLI.

    Parses command-line arguments and dispatches to the appropriate handler.
    """
    # Init parser
    parser = argparse.ArgumentParser()

    # Add argments to parser
    parser.add_argument("-v", "--verbose", help="Displays verbose logging to console", action="store_true") # args without action require CLI input. Action specifies what should happen if arg is passed in CLI

    # Parse passed args
    args = parser.parse_args() # Creates --help and usage information



    #Create functionality for passed args
    if args.verbose:
        print("verbosity turned on") # CLI input test script (Remove later)



if __name__ == "__main__":
    main()