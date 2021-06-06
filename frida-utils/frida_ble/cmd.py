import argparse
from .core import FridaBLETools
from .constants import HOOKS_DIR


def _setup_scan_parser(subparsers):
    scan_parser = subparsers.add_parser("scan", help="Hook onto ScanResponse callback")


def _setup_enumerate_parser(subparsers):
    enum_parser = subparsers.add_parser(
        "enumerate",
        help="Hook onto BluetoothGattCallback and getServices()",
    )


def _setup_monitor_parser(subparsers):
    monitor_parser = subparsers.add_parser(
        "monitor", help="Hook onto BluetoothGattCallback"
    )


def _setup_fuzz_parser(subparsers):
    monitor_parser = subparsers.add_parser(
        "fuzz", help="Hook onto BluetoothGattWrite and send random data"
    )


def _setup_parser():
    parser = argparse.ArgumentParser(description="Frida utilities for BLE testing")
    parser.add_argument(
        "app", type=str, help="Enter full application package name. e.g. com.govee.home"
    )

    subparsers = parser.add_subparsers(
        description="Available BLE tools", required=True, dest="command"
    )
    _setup_scan_parser(subparsers)
    _setup_enumerate_parser(subparsers)
    _setup_monitor_parser(subparsers)
    _setup_fuzz_parser(subparsers)

    return parser


def _wait():
    try:
        print("Press any button to exit.")
        input()
    except KeyboardInterrupt:
        pass

    print("Done ...")


def cli():
    p = _setup_parser()
    args = p.parse_args()
    print(args)
    ble_tools = FridaBLETools(args.app)

    if args.command == "scan":
        ble_tools.scan()
        _wait()
    elif args.command == "monitor":
        ble_tools.monitor()
        _wait()
    elif args.command == "enumerate":
        ble_tools.enumerate()
        _wait()
    elif args.command == "fuzz":
        ble_tools.fuzz()
        _wait()
    else:
        raise NotImplementedError(f"Command {args.command} not implemted")
