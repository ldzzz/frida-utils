from colorlog import ColoredFormatter
import argparse
import logging
import frida
import sys
import os
from . import core

logger = logging.getLogger('debug_logger')
logger.setLevel(logging.INFO)

def _parse_args():
    """Method creates command line parser and parses the options accordingly."""
    parser = argparse.ArgumentParser(prog='frida-monitor', description='Monitor tool for Android apps using Frida.')
    parser.add_argument('package', help='Package name of the app')
    subparsers = parser.add_subparsers(dest='chosen_monitor', help='Monitor different things')

    parser_network = subparsers.add_parser('L', help='Monitor libc (recv and send - alike functions)')
    parser_network.add_argument("-e", "--extras", action='store_true', help="Print extra information about IPs")
    parser_network.add_argument("-b", "--buffer", action='store_true', help="Print buffer data sent and received")

    parser_threads = subparsers.add_parser('JC', help='Monitor Java crypto methods')

    parser.add_argument('-v', '--verbose', action='store_true', help='Output additional info logs to terminal')
    params = parser.parse_args()
    logger.debug('Params received: %s', params)
    return params


def _setup_cmd_logger():
    """Sets up logger to enable printing to the command line."""
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    formatter = ColoredFormatter('%(log_color)s[%(levelname)8s] %(message)s%(reset)s')
    ch.setLevel(level=logging.DEBUG)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def start_cmd():
    try:
        args = _parse_args()

        if args.verbose:
            _setup_cmd_logger()

        core.execute_enumerator(args)
    except KeyboardInterrupt:
        sys.exit(0) 


if __name__ == '__main__':
    start_cmd()