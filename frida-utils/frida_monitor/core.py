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

def on_message(msg, data):
    print('*'*40)
    print(msg)
    print(data)

def parse_args_list(l):
    if not l:
        return l
    pl = l.replace(", ", ",").replace(" ", ",").split(",")
    return pl

def execute_enumerator(args):
    printerManager.print_msg('Spawning ' + args.package, MessageCode.INFO)

    try:
        pid = frida.get_usb_device().spawn(args.package)
        session = frida.get_usb_device().attach(pid)
        hook = open(os.path.join(HOOK_PATH, 'libcMonitor.js'), 'r')
        script = session.create_script(hook.read())
        script.on('message', on_message)
        script.load() 
        frida.get_usb_device().resume(pid)
        sys.stdin.read()
    except Exception as e:
        logger.debug(str(e).capitalize())
        printerManager.print_msg(str(e).capitalize(), MessageCode.ERROR)
        exit(0)