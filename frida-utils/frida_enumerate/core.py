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


def parse_args_list(l):
    if not l:
        return l
    pl = l.replace(", ", ",").replace(" ", ",").split(",")
    return pl

def execute_enumerator(args):
    printerManager.print_msg('Spawning ' + args.package, MessageCode.INFO)
    chosen_enumerator = None 

    # parse include/exclude lists
    if not hasattr(args, 'include'):
        args.include = None
    if not hasattr(args, 'exclude'):
        args.exclude = None
    
    args.include = parse_args_list(args.include)
    args.exclude = parse_args_list(args.exclude)

    printerManager.print_msg("Include list: {}".format(args.include))
    printerManager.print_msg("Exclude list: {}".format(args.exclude))


    if args.chosen_enum == 'M':
        from .enumerators.module_enumerator import ModuleEnumerator
        chosen_enumerator = ModuleEnumerator(package=args.package, includes=args.include, excludes=args.exclude, pm=printerManager)
    elif args.chosen_enum == 'T':
        from .enumerators.thread_enumerator import ThreadEnumerator
        chosen_enumerator = ThreadEnumerator(args.package, printerManager)
    elif args.chosen_enum == 'E':
        from .enumerators.exports_enumerator import ExportsEnumerator
        chosen_enumerator = ExportsEnumerator(package=args.package, includes=args.include, excludes=args.exclude, pm=printerManager)
    elif args.chosen_enum == 'I':
        from .enumerators.imports_enumerator import ImportsEnumerator
        chosen_enumerator = ImportsEnumerator(package=args.package, includes=args.include, excludes=args.exclude, pm=printerManager)
    elif args.chosen_enum == 'J':
        from .enumerators.java_enumerator import JavaEnumerator
        chosen_enumerator = JavaEnumerator(package=args.package, includes=args.include, excludes=args.exclude, pm=printerManager)

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