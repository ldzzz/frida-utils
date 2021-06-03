from colorama import Fore, Style
from enum import Enum


class MessageCode(Enum):
    INFO = 1
    WARN = 2
    ERROR = 3


class PrinterManager():
    def __init__(self):
        self._color_palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
        self._next_color = 0

    def _get_color(self):
        chosen_color = self._color_palette[self._next_color % len(self._color_palette)]
        self._next_color += 1
        return chosen_color

    def print_msg(self, s, event=None):
        s = '[*] {}'.format(s)
        if event == MessageCode.ERROR:
            print(Fore.RED + s + Fore.RESET)
        elif event == MessageCode.WARN:
            print(Fore.YELLOW + s + Fore.RESET)
        elif event == MessageCode.INFO:
            print(Fore.GREEN + s + Fore.RESET)
        else:
            print(s)

    def _print_single_module(self, module):
        name = module.get('name')
        base = module.get('base')
        size = module.get('size')
        path = module.get('path')

        color = self._get_color()
        msg = color
        
        msg +=  "[*] Module: {}\n" \
                " |---- Base address: {}\n" \
                " |---- Size: {}\n" \
                " |---- Path: {}".format(name, base, size, path)
        
        msg += Fore.RESET
        print(msg)

    def print_modules(self, payload):
        modules = payload.get('modules')
        self.print_msg("Found modules:\n", MessageCode.INFO)

        for e in modules:
            self._print_single_module(e)


