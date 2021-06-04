from .abstract_enumerator import AbstractEnumerator
from frida_enumerate.constants import HOOK_PATH
from frida_enumerate.helpers import PrinterManager, MessageCode
import logging
import frida
import os

logger = logging.getLogger('debug_logger')

class ModuleEnumerator(AbstractEnumerator):
    def __init__(self, package):
        self._session = None
        self._package = package
        self._plist = None
        self._hook_fname = os.path.join(HOOK_PATH, "moduleEnumerator.js")
        self._pm = PrinterManager()


    def parse_payload(self, payload):
        modules = payload.get('modules')
        self._plist = []
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

    def attach_hook(self):
        logger.debug('[*] Parsing hook: ' + self._hook_fname)
        self._pm.print_msg("Attaching hook file: " + self._hook_fname, MessageCode.INFO)
        hook = open(self._hook_fname, 'r')
        script = self._session.create_script(hook.read())
        script.on('message', self.on_message)
        script.load() 

    def run(self):
        self._pm.print_msg('Running module enumerator', MessageCode.INFO)

        try:
            pid = frida.get_usb_device().spawn(self._package)
            self._session = frida.get_usb_device().attach(pid)
            self.attach_hook()
            frida.get_usb_device().resume(pid)
        except Exception as e:
            logger.debug(str(e).capitalize() + " check if device connected !")
            self._pm.print_msg(str(e).capitalize(), MessageCode.ERROR)
            exit(0)

        # Print parsed payload
        self._pm.print_msg("Found modules:\n", MessageCode.INFO)
        self._pm.print_list(self._plist)