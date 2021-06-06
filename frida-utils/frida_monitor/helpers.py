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
            print(Fore.RED + Style.BRIGHT + s + Fore.RESET)
        elif event == MessageCode.WARN:
            print(Fore.YELLOW + Style.BRIGHT + s + Fore.RESET)
        elif event == MessageCode.INFO:
            print(Fore.GREEN + Style.BRIGHT + s + Fore.RESET)
        else:
            print(s)

    def print_list(self, plist):
        for e in plist:
            print(self._get_color() + Style.BRIGHT + e + Fore.RESET)

    def print_network(self, e, event):
        if event in 'recvfrom':
            print(Fore.RED + Style.BRIGHT + e + Fore.RESET)
        elif event in 'sendto':
            print(Fore.GREEN + Style.BRIGHT + e + Fore.RESET)



