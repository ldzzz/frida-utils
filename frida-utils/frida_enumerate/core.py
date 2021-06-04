from .helpers import MessageCode, PrinterManager
from colorlog import ColoredFormatter
from .constants import HOOK_PATH
import argparse
import logging
import frida
import sys
import os

logger = logging.getLogger('debug_logger')
printerManager = PrinterManager()

def execute_enumerator(args):
    printerManager.print_msg('Spawning ' + args.package, MessageCode.INFO)
    if args.chosen_enum == 'M':
        from .enumerators.module_enumerator import ModuleEnumerator
        moen = ModuleEnumerator(args.package)
        moen.run()
    elif args.chosen_enum == 'T':
        pass