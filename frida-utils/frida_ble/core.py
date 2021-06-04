import sys
import frida
import logging

from .constants import HOOKS_DIR
logger = logging.getLogger(__name__)


def _read_script(script_name):
    to_inject = None
    with open(script_name) as f:
        to_inject = f.read()
    logger.debug(to_inject)
    return to_inject


def run(script_path, app_name):
    to_inject = _read_script(script_path)
    try:
        device = frida.get_usb_device()
    except frida.InvalidArgumentError:
        print("Device not found.")
        exit(-1)

    pid = device.spawn([app_name])
    session = device.attach(pid)
    script = session.create_script(to_inject)
    script.load()
    device.resume(pid)
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("Bye ... ")


if __name__ == "__main__":
    run(HOOKS_DIR / "ble_enumerate.js", "com.govee.home")
