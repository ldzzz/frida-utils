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
    chosen_enumerator = None 
    if args.chosen_enum == 'M':
        from .enumerators.module_enumerator import ModuleEnumerator
        chosen_enumerator = ModuleEnumerator(package=args.package, includes=None, excludes=None, pm=printerManager)
    elif args.chosen_enum == 'T':
        from .enumerators.thread_enumerator import ThreadEnumerator
        chosen_enumerator = ThreadEnumerator(args.package, printerManager)

    try:
        pid = frida.get_usb_device().spawn(chosen_enumerator.package)
        chosen_enumerator._session = frida.get_usb_device().attach(pid)
        hook = chosen_enumerator.get_hook()
        script = chosen_enumerator._session.create_script(hook)
        script.on('message', chosen_enumerator.on_message)
        script.load() 
        frida.get_usb_device().resume(pid)
        chosen_enumerator.run() #TODO: rework probably not needed run function
    except Exception as e:
        logger.debug(str(e).capitalize())
        printerManager.print_msg(str(e).capitalize(), MessageCode.ERROR)
        exit(0)