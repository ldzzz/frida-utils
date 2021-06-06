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
        event       = payload.get('event')
        fd          = payload.get('fd')
        stype       = payload.get('socktype')
        ip          = payload.get('sockaddr').get('ip')
        port        = payload.get('sockaddr').get('port')

        txt = "[*] {}".format(event.upper())
        s = "\n" + " "*4 + "|-- "
        txt += "%s%4s" % (s, fd)
        txt += "%s%4s" % (s, stype)
        txt += "%s%4s" % (s, port)  
        txt += "%s %s" % (s, ip)
        self._pm.print_network(txt, event=event)        

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