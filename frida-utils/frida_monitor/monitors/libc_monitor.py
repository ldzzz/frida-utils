from frida_monitor.helpers import PrinterManager, MessageCode
from frida_monitor.constants import HOOK_PATH
from .abstract_monitor import AbstractMonitor
from frida_monitor.utils import ip_info
import logging
import frida
import os

logger = logging.getLogger('debug_logger')


class LibcMonitor(AbstractMonitor):
    def __init__(self, package, extras, buf, pm):
        self._hook_fname = os.path.join(HOOK_PATH, "libcMonitor.js")
        self.package = package
        self._session = None
        self._plist = None
        self._extras = extras
        self._buf = buf
        self._pm = pm
    
    def parse_payload(self, payload):
        event       = payload.get('event')
        fd          = payload.get('fd')
        stype       = payload.get('socktype')
        ip          = payload.get('sockaddr').get('ip')
        port        = payload.get('sockaddr').get('port')
        buf         = payload.get('buffer')

        txt = "[*] {}".format(event.upper())
        s = "\n" + " "*4 + "|-- "
        txt += "%s%8s" % (s, 'FD: ' + str(fd))
        txt += "%s %8s" % (s, 'Socket Type: ' + stype)
        txt += "%s %8s" % (s, 'Port: ' + str(port))  
        txt += "%s %s" % (s, 'IP: ' + ip)

        if self._buf and buf:
            txt += "%s %s" % (s, 'BUFFER DATA: ' + buf)

        if self._extras:
            ip_extras = ip_info(ip)
            v = 'Version: {}'.format(ip_extras.get('version'))
            cc = 'Location: {}, {}'.format(ip_extras.get('city'), ip_extras.get('country_name'))
            org = 'ORG: {}'.format(ip_extras.get('org'))

            txt += '\n'
            s = " "*4 + "|-- "
            txt += ' '*5 + "%s%4s\n" % (s, v)
            txt += ' '*5 + "%s%4s\n" % (s, cc)
            txt += ' '*5 + "%s%4s\n" % (s, org)
        
        txt += '-'*50
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