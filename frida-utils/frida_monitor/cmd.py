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
    """Method creates command line parser and parses the options accordingly.

    Returns:parsed arguments

        Namespace: argparse object containing parsed parameters
    """
    parser = argparse.ArgumentParser(prog='frida-monitor', description='Monitor tool for Android apps using Frida.')
    parser.add_argument('package', help='Package name of the app')

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