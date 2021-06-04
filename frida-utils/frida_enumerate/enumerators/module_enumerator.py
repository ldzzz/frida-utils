from .abstract_enumerator import AbstractEnumerator
from frida_enumerate.constants import HOOK_PATH
from frida_enumerate.helpers import PrinterManager, MessageCode
import logging
import frida
import os

logger = logging.getLogger('debug_logger')

class ModuleEnumerator(AbstractEnumerator):
    def __init__(self, package, includes, excludes, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "moduleEnumerator.js")
        self.package = package
        self._includes = includes
        self._exclude = excludes
        self._session = None
        self._plist = None
        self._pm = pm


    def parse_payload(self, payload):
        modules = payload.get('modules')
        self._plist = []
        #TODO: based on includes/excludes
        for e in modules:
            txt = "[*] Module: {}".format(e.pop('name'))
            for k,v in e.items():
                txt += "\n" + " |---- {}: {}".format(k, v)
            self._plist.append(txt)

    def on_message(self, message, data):
        logger.debug('Callback triggered')
        self._pm.print_msg("Received enumeration of all modules", MessageCode.INFO)
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
        # Print parsed payload
        self._pm.print_msg("Found modules:\n", MessageCode.INFO)
        self._pm.print_list(self._plist)