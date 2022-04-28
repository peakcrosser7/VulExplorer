import io
import signal
import sys
import types
from typing import Dict, Optional

from utils.log import *


class Cmd:
    def __init__(self, func, args_type: list, desc: str):
        self.func = func
        self.args_type = args_type
        self.desc = desc


class CmdEngine:
    def __init__(self, logo=''):
        self._default: Dict[str, Cmd] = {}
        self._group: Dict[str, Dict[str, Cmd]] = {}
        self._logo = logo

        self.register_func(self._quit_cmdline, [], 'q', desc='quit cmdline')
        self.register_func(self._show_help, [self], 'help', desc='show help message')
        signal.signal(signal.SIGINT, self.sigint_handler)

        self._run_logo_func()

    def _run_logo_func(self):
        if self._logo:
            print(self._logo)

    @staticmethod
    def sigint_handler(signum, frame):
        print('')
        sys.exit()

    def register_group(self, group: str):
        if group == '':
            perr('group name should not be empty')
            sys.exit()
        if group in self._group:
            perr('group is existed')
            sys.exit()
        self._group[group] = {}

    @classmethod
    def _register_func(cls, cmd_dict: Dict[str, Cmd], func, args_type: list, label: str,
                       desc: str = ''):
        if func.__code__.co_argcount != len(args_type):
            perr('the args_type is not match the function in label "%s"' % label)
            sys.exit()
        cmd_dict[label] = Cmd(func, args_type, desc)

    def register_func(self, func, args_type: list, label: str, group: str = '',
                      desc: str = ''):
        if group == '':
            self._register_func(self._default, func, args_type, label, desc)
            return

        if group not in self._group:
            perr('group is not existed')
            sys.exit()
        self._register_func(self._group[group], func, args_type, label, desc)

    def _check_cmd(self, args) -> int:
        cmd = args[0]
        if cmd == '':
            return 0
        if cmd in self._default:
            return 1
        if len(args) == 1:
            perr('command not exist, you can use \'help\' to see all commands')
            return 0
        group = args[0]
        cmd = args[1]
        if group in self._group and cmd in self._group[group]:
            return 2
        perr('command not exist, you can use \'help\' to see all commands')
        return 0

    @staticmethod
    def _check_param(args_type, input_args) -> Optional[list]:
        new_args = []
        i = 0
        for arg in args_type:
            try:
                if arg == int:
                    arg = int(input_args[i])
                    i += 1
                elif arg == float:
                    arg = float(input_args[i])
                    i += 1
                elif arg is None:
                    arg = input_args[i]
                    i += 1
            except IndexError:
                perr('the count of params in command is not right')
                return None
            except ValueError:
                perr('the type of param \'%s\' is not "%s"' % (input_args[i], arg.__name__))
                return None
            new_args.append(arg)
        return new_args

    def run_func(self, args_str: str):
        args = args_str.split()
        start = self._check_cmd(args)
        cmd: Cmd
        if start == 1:
            cmd = self._default[args[0]]
        elif start == 2:
            cmd = self._group[args[0]][args[1]]
        else:
            return

        args_type = cmd.args_type[1:] if self._is_class_func(cmd.func) else cmd.args_type
        new_args = self._check_param(args_type, args[start:])
        if new_args is not None:
            cmd.func(*new_args)

    @staticmethod
    def _is_class_func(func) -> bool:
        return isinstance(func, types.MethodType)

    @classmethod
    def _show_cmd(cls, label, cmd: Cmd):
        sio = io.StringIO()
        sio.write('    ')
        sio.write(label)
        sio.write('  ')
        i = 1 if cls._is_class_func(cmd.func) else 0
        for i in range(i, len(cmd.args_type)):
            sio.write('<')
            sio.write(cmd.func.__code__.co_varnames[i])
            sio.write('> ')
        print('%-35s - %s' % (sio.getvalue(), cmd.desc))

    def _show_help(self):
        print('VulExplorer Usage: [group] <command> [arg0 arg1 ...]\n')
        print('Generic Command:')
        for label, cmd in self._default.items():
            self._show_cmd(label, cmd)
        for group, cmds in self._group.items():
            print('\nGroup: %s' % group)
            for label, cmd in cmds.items():
                self._show_cmd(label, cmd)
        print('')

    @staticmethod
    def _quit_cmdline():
        sys.exit()
