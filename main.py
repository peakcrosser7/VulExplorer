import os.path
import sys

import global_config
from utils.cmd_engine import CmdEngine
from dataset_handler.handler import DataHandlerFactory, DatasetHandler
from utils.log import *


def init():
    global_config.DATASET_DIR = os.path.abspath(global_config.DATASET_DIR)


def tester(s: int, n: int):
    for i in range(s, n):
        print(i)


def check_dataset(checked_str: str, handler: DatasetHandler):
    checked_set = set()
    checked_list = checked_str.split(',')
    for checked_it in checked_list:
        checked_it = checked_it.strip()
        try:
            if '-' in checked_it:
                num_range = checked_it.split('-')
                begin, back = int(num_range[0]), int(num_range[1])
                for i in range(begin, back + 1):
                    checked_set.add(i)
            else:
                checked_set.add(int(checked_it))
        except:
            perr('input args is not right')
            return

    if handler.check_dataset(checked_set):
        pinfo('check dataset successfully')


def main():
    init()

    cmd_engine = CmdEngine('VulExplorer')
    cmd_engine.register_func(tester, [int, int], 'test', desc='run test')
    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    cmd_engine.register_group('dataset')
    cmd_engine.register_func(json_handler.show_dataset, [], 'show', group='dataset',
                             desc='show all vuls in dataset')
    cmd_engine.register_func(check_dataset, [None, json_handler], 'check', 'dataset',
                             desc='checked dataset to compare')
    while True:
        ipt = input('>> ')
        cmd_engine.run_func(ipt)


if __name__ == '__main__':
    main()
