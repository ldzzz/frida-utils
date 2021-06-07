from frida_monitor.helpers import PrinterManager, MessageCode
from frida_monitor.constants import HOOK_PATH
from .abstract_monitor import AbstractMonitor
from frida_monitor.utils import ip_info
import logging
import frida
import os

logger = logging.getLogger('debug_logger')


class DynamicMonitor(AbstractMonitor):
    def __init__(self, package, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "dynamicMonitor.js")
        self.package = package
        self._session = None
        self._plist = None
        self._pm = pm
    
    def parse_payload(self, payload):
        print(payload)

    def on_message(self, message, data):
        try:
            if message:
                if message['type'] == 'send':
                    payload = message['payload']
                    self.parse_payload(payload)
        except Exception as e:
            print('exception: {}'.format(e))

    def get_hook(self):
        logger.debug('[*] Parsing hook: ' + self._hook_fname)
        self._pm.print_msg("Attaching hook file: " + self._hook_fname, MessageCode.INFO)
        hook = open(self._hook_fname, 'r')
        return hook.read()

    def run(self): #TODO: rework probably not needed
        self._pm.print_msg("Going to monitor libc:\n", MessageCode.INFO)