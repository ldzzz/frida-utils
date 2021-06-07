from colorama import Fore, Style
from enum import Enum


class MessageCode(Enum):
    INFO = 1
    WARN = 2
    ERROR = 3


class PrinterManager():
    def __init__(self):
        self._color_palette = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.RED, Fore.BLUE]
        self._next_color = 2

    def _get_color(self):
        chosen_color = self._color_palette[self._next_color % len(self._color_palette)]
        #self._next_color += 1
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

    def print_list(self, plist):
        for e in plist:
            print(self._get_color() + e + Fore.RESET)



