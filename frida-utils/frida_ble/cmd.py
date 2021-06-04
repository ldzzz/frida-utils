from .core import run
from .constants import HOOKS_DIR


def start_cmd():
    run(HOOKS_DIR / "ble_enumerate.js", "com.govee.home")
