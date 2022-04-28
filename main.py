import os.path

import global_config
from utils.cmd_engine import CmdEngine
from dataset_handler.handler import DataHandlerFactory


def tester(s: int, n: int):
    for i in range(s, n):
        print(i)


def init():
    global_config.DATASET_DIR = os.path.abspath(global_config.DATASET_DIR)


def main():
    init()

    cmd_engine = CmdEngine('VulExplorer')
    cmd_engine.register_func(tester, [int, int], 'test', desc='run test')
    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    cmd_engine.register_group('dataset')
    cmd_engine.register_func(json_handler.show_dataset, [json_handler], 'show', group='dataset',
                             desc='show all vuls in dataset')
    while True:
        ipt = input('>> ')
        cmd_engine.run_func(ipt)


if __name__ == '__main__':
    main()
