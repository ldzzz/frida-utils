from .abstract_monitor import AbstractMonitor
from frida_monitor.constants import HOOK_PATH
from frida_monitor.helpers import PrinterManager, MessageCode
import logging
import frida
import os

logger = logging.getLogger('debug_logger')


class LibcMonitor(AbstractMonitor):
    def __init__(self, package, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "libcMonitor.js")
        self.package = package
        self._session = None
        self._plist = None
        self._pm = pm
    
    def parse_payload(self, payload):
        print(payload)
        '''
        exports = payload.get('exports')
        exports = self._include_exclude_modules_by_name(exports)
        self._plist = []
        txt = ""
        for k,v in exports.items():
            txt = "[*] Module: {}".format(k)
            for ex in v:
                for kk, vv in ex.items():
                    txt += "\n" + " |---- {}: {}".format(kk, vv)
                txt += "\n" + " "*2 + "-"*50
            self._plist.append(txt)
        '''

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
        self._pm.print_msg("Found exports:\n", MessageCode.INFO)
        self._pm.print_list(self._plist)