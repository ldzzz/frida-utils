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

def enumerate_print(message, data):
    logger.debug('Entered enumerate_print')
    printerManager.print_msg("Received enumeration of all modules", MessageCode.INFO)
    try:
        if message:
            if message['type'] == 'send':
                payload = message['payload']
                printerManager.print_modules(payload)
    except Exception as e:
        print('exception: {}'.format(e)) 


def attach_hook(session):
    filename = os.path.join(HOOK_PATH, "enumerateAll.js")
    logger.debug('[*] Parsing hook: ' + filename)
    hook = open(filename, 'r')
    #TODO: load corresponding .js based on chosen argparse, for now lets enumerate all
    script = session.create_script(hook.read())
    script.on('message', enumerate_print)
    script.load() 


def run(args):
    printerManager.print_msg('Spawning ' + args.package, MessageCode.INFO)
    pid = frida.get_usb_device().spawn(args.package)
    session = frida.get_usb_device().attach(pid)
    attach_hook(session)
    frida.get_usb_device().resume(pid)
    print('')
    exit(0)
    