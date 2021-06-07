import argparse
from random import choices
from .core import FridaBLETools, BLE_METHODS


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
        "fuzz", help="Hook on to desired action and start fuzzing"
    )
    monitor_parser.add_argument("uuid", help="UUID to be fuzzed.", type=str)
    monitor_parser.add_argument(
        "method",
        help="On which method should the fuzzing for given UUID be applied",
        nargs="+",
        type=str,
        choices=BLE_METHODS,
    )
    monitor_parser.add_argument(
        "-i",
        "--ignore-messages",
        dest="ignore",
        type=int,
        help="Ignore first N messages, before fuzzing start.",
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
        ble_tools.fuzz(args.uuid, args.method, args.ignore)
        _wait()
    else:
        raise NotImplementedError(f"Command {args.command} not implemted")
