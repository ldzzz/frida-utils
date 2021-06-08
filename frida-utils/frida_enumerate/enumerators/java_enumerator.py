from .abstract_enumerator import AbstractEnumerator
from frida_enumerate.constants import HOOK_PATH
from frida_enumerate.helpers import PrinterManager, MessageCode
import logging
import frida
import os

logger = logging.getLogger('debug_logger')

class JavaEnumerator(AbstractEnumerator):
    def __init__(self, package, includes, excludes, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "javaEnumerator.js")
        self.package = package
        self._includes = includes
        self._excludes = excludes
        self._session = None
        self._plist = None
        self._pm = pm
        self._available = True

    def _include_exclude_classes_by_name(self, classes):
        ie_mods = []
        if self._excludes:
            for ind, e in enumerate(classes):
                if any(string in e for string in self._excludes):
                    classes.pop(ind)
        if self._includes:
            for e in classes:
                if any(string in e for string in self._includes):
                    ie_mods.append(e)
        else:
            ie_mods = classes
        return ie_mods

    def parse_payload(self, payload):
        self._available = payload.get('available')
        self._pm.print_msg('Java available: {}'.format(self._available), MessageCode.INFO if  self._available else MessageCode.ERROR)
        if not self._available:
            return
        
        classes = payload.get('java_classes')
        classes = self._include_exclude_classes_by_name(classes)
        self._plist = []
        for e in classes:
            txt = "[*] Class: {}".format(e)
            self._plist.append(txt)
    
    def on_message(self, message, data):
        logger.debug('Callback triggered')
        self._pm.print_msg("Received enumeration of all Java classes", MessageCode.INFO)
        try:
            if message and message['type'] == 'send':
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
        if self._available:
            self._pm.print_msg("Found Java classes:\n", MessageCode.INFO)
            self._pm.print_list(self._plist)