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
    chosen_monitor = None
    
    if args.chosen_monitor == 'L':
        from .monitors.libc_monitor import LibcMonitor
        chosen_monitor = LibcMonitor(package=args.package, extras=args.extras, buf=args.buffer, pm=printerManager)
    else:
        print('No recognized monitor value')
        return

    try:
        pid = frida.get_usb_device().spawn(chosen_monitor.package)
        chosen_monitor._session = frida.get_usb_device().attach(pid)
        hook = chosen_monitor.get_hook()
        script = chosen_monitor._session.create_script(hook)
        script.on('message', chosen_monitor.on_message)
        script.load() 
        frida.get_usb_device().resume(pid)
        sys.stdin.read()
    except Exception as e:
        logger.debug(str(e).capitalize())
        printerManager.print_msg(str(e).capitalize(), MessageCode.ERROR)
        exit(0)