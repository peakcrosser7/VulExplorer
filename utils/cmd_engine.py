import io
import signal
import sys
import types
from typing import Dict, Optional, List

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
        self._trans_types = {
            int: int,
            float: float,
        }

        self.register_func(self._quit_cmdline, [], 'q', desc='quit cmdline')
        self.register_func(self._show_help, [], 'help', desc='show help message')
        signal.signal(signal.SIGINT, self.sigint_handler)

        self._run_logo_func()

    def _run_logo_func(self):
        if self._logo:
            print(self._logo)

    def add_trans_type(self, trans_type, trans_func):
        self._trans_types[trans_type] = trans_func

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
        arg_cnt = func.__code__.co_argcount
        if cls._is_class_func(func):
            arg_cnt -= 1
        if arg_cnt != len(args_type):
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
        if len(args) == 0:
            return 0
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

    def _check_param(self, args_type, input_args) -> Optional[list]:
        new_args = []
        i = 0
        for arg in args_type:
            try:
                if arg in self._trans_types:
                    arg = self._trans_types[arg](input_args[i])
                    i += 1
                elif arg is None:
                    arg = input_args[i]
                    i += 1
            except IndexError:
                perr('the count of params in command is not right')
                return None
            except:
                perr('the type of param \'%s\' is not "%s"' % (input_args[i], arg.__name__))
                return None

            new_args.append(arg)
        return new_args

    def run_func(self, args: List[str]):
        start = self._check_cmd(args)
        cmd: Cmd
        if start == 1:
            cmd = self._default[args[0]]
        elif start == 2:
            cmd = self._group[args[0]][args[1]]
        else:
            return

        new_args = self._check_param(cmd.args_type, args[start:])
        if new_args is not None:
            cmd.func(*new_args)

    @staticmethod
    def _is_class_func(func) -> bool:
        return isinstance(func, types.MethodType)

    def _show_cmd(self, label, cmd: Cmd):
        sio = io.StringIO()
        sio.write('    ')
        sio.write(label)
        sio.write('  ')
        i = 1 if self._is_class_func(cmd.func) else 0
        for arg in cmd.args_type:
            if arg is None or arg in self._trans_types:
                sio.write('<')
                sio.write(cmd.func.__code__.co_varnames[i])
                sio.write('> ')
            i += 1
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
