import os.path
import time

import global_config
from cmpWFDG import detect
from dataset_handler.handler import DataHandlerFactory, DatasetHandler
from utils.cmd_engine import CmdEngine
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


def get_time_str(timestamp: float):
    m, s = divmod(timestamp, 60)
    h, m = divmod(m, 60)
    return '%02d:%02d:%02d' % (h, m, s)


def detect_vuls(handler: DatasetHandler):
    dataset = handler.get_dataset()
    if not dataset:
        return
    start_time = time.time()
    pinfo('start vulnerability detection at %s, detection path: %s, head path: %s'
          % (get_time_str(start_time), global_config.DETECT_PATH, global_config.HEAD_PATH))
    detect.detect_by_cmp(global_config.DETECT_PATH, global_config.HEAD_PATH, dataset)
    end_time = time.time()
    pinfo('end vulnerability detection at %s' % get_time_str(end_time))
    pinfo('detection cost time: %s' % get_time_str(end_time - start_time))


def show_config():
    settings = dir(global_config)
    print('\t%-25s | %s' % ('Item', 'Value'))
    for setting in settings:
        if not setting.startswith('__') or not setting.endswith('__'):
            print('\t%-25s   %s' % (setting, getattr(global_config, setting)))


def set_config(config_item: str, new_value: str):
    settings = dir(global_config)
    if config_item not in settings:
        perr('the config item does not exist')
        return
    t = type(getattr(global_config, config_item))
    try:
        if t == str:
            setattr(global_config, config_item, new_value)
        elif t == int:
            setattr(global_config, config_item, int(new_value))
        elif t == float:
            setattr(global_config, config_item, float(new_value))
        else:
            perr('the type of config item is not supported')
            return
    except ValueError:
        perr('the type of param \'%s\' is not "%s"' % (new_value, t.__name__))
        return
    pinfo('the config item "%s" update successfully' % config_item)


def main():
    cmd_engine = CmdEngine('VulExplorer')
    cmd_engine.register_func(tester, [int, int], 'test', desc='run test')

    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    json_handler.set_dataset_dir(global_config.DATASET_DIR)
    cmd_engine.register_group('dataset')
    cmd_engine.register_func(json_handler.show_dataset, [], 'show', group='dataset',
                             desc='show all vuls in dataset')
    cmd_engine.register_func(check_dataset, [None, json_handler], 'check', group='dataset',
                             desc='checked dataset to compare')

    cmd_engine.register_group('config')
    cmd_engine.register_func(show_config, [], 'show', group='config', desc='show all configurations')
    cmd_engine.register_func(set_config, [None, None], 'set', group='config', desc='set config item a new value')

    while True:
        ipt = input('>> ')
        cmd_engine.run_func(ipt)


if __name__ == '__main__':
    main()
