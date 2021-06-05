import os
import frida
import logging
from pathlib import Path

from .constants import HOOKS_DIR

logger = logging.getLogger(__name__)


def _read_script(script_name):
    to_inject = None
    with open(HOOKS_DIR / script_name) as f:
        to_inject = f.read()
    logger.debug(to_inject)
    return to_inject


class FridaBLETools:
    def __init__(self, app_name, **kwargs):
        self._app_name = app_name
        self._report_dir = kwargs.get("report_dir", Path.cwd() / "ble_report")
        try:
            self._device = frida.get_usb_device()
        except frida.InvalidArgumentError:
            raise ValueError("Could not find any phones connected.")
        self._script = None

    def _run_frida_script(self, script):
        hook_script = _read_script(script)
        pid = self._device.spawn([self._app_name])
        session = self._device.attach(pid)
        self._script = session.create_script(hook_script)
        self._script.load()
        self._device.resume(pid)

    def scan(self):
        self._run_frida_script("ble_scan.js")

    def monitor(self):
        self._run_frida_script("ble_monitor.js")

    def enumerate(self):
        self._run_frida_script("ble_enumerate.js")

    def fuzz(self):
        self._run_frida_script("ble_fuzz.js")
        print(self._script._rpc_request("list"))
        set_uuid = getattr(self._script.exports, "setuuid")
        uuid = "00010203-0405-0607-0809-0a0b0c0d2b10"
        set_uuid(uuid)
        print("Done setting uuid")
