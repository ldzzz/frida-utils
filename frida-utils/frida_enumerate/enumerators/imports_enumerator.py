from .abstract_enumerator import AbstractEnumerator
from frida_enumerate.constants import HOOK_PATH
from frida_enumerate.helpers import PrinterManager, MessageCode
import logging
import frida
import os

logger = logging.getLogger('debug_logger')


class ImportsEnumerator(AbstractEnumerator):
    def __init__(self, package, includes, excludes, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "importsEnumerator.js")
        self.package = package
        self._includes = includes
        self._excludes = excludes
        self._session = None
        self._plist = None
        self._pm = pm

    def _include_exclude_modules_by_name(self, modules):
        if self._excludes:
            for k in modules.copy():
                if any(string in k for string in self._excludes):
                    modules.pop(k)
        if self._includes:
            for k in modules.copy():
                if not any(string in k for string in self._includes):
                    modules.pop(k)
        return modules
    
    def parse_payload(self, payload):
        imports = payload.get('imports')
        imports = self._include_exclude_modules_by_name(imports)
        self._plist = []
        txt = ""
        for k,v in imports.items():
            txt = "[*] Module: {}".format(k)
            for ex in v:
                for kk, vv in ex.items():
                    txt += "\n" + " |---- {}: {}".format(kk, vv)
                txt += "\n" + " "*2 + "-"*50
            self._plist.append(txt)

    def on_message(self, message, data):
        logger.debug('Callback triggered')
        self._pm.print_msg("Received enumeration of all imports", MessageCode.INFO)
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
        self._pm.print_msg("Found imports:\n", MessageCode.INFO)
        self._pm.print_list(self._plist)