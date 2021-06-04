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
        self._excludes = excludes
        self._session = None
        self._plist = None
        self._pm = pm

    def _include_exclude_modules_by_name(self, modules):
        ie_mods = []
        if self._excludes:
            for ind, e in enumerate(modules):
                if any(string in e.get('name') for string in self._excludes):
                    modules.pop(ind)


        print(self._includes)
        if self._includes:
            for e in modules:
                if any(string in e.get('name') for string in self._includes):
                    ie_mods.append(e)
        else:
            ie_mods = modules
        return ie_mods

    def parse_payload(self, payload):
        modules = payload.get('modules')
        modules = self._include_exclude_modules_by_name(modules)
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