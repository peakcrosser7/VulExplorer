import json
import os.path
import sys

import global_config
from cmpWFDG import detect
from dataset_handler.handler import DataHandlerFactory, DatasetHandler
from genWFDG import gen_wfdg
from genWFDG import config_trans
from utils import my_time
from utils.cmd_engine import CmdEngine
from utils.log import *


def check_dataset(checked_str: str, handler: DatasetHandler):
    """选中用于检测的数据集"""
    checked_set = set()
    if checked_str != '-':
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


def save_detect_result(vul_result: list):
    if not os.path.exists(global_config.OUTPUT_DIR):
        os.makedirs(global_config.OUTPUT_DIR)
    save_path = os.path.join(global_config.OUTPUT_DIR, 'detect_result.json')
    with open(save_path, 'w') as wf:
        json.dump(vul_result, wf)


def detect_vuls(handler: DatasetHandler):
    """进行漏洞检测"""
    ds = handler.get_checked_dataset()
    if not ds:
        pwarn('no checked dataset')
        return
    dataset = []
    config_tran = config_trans.ConfigTrans(global_config.WEIGHT_PRED_RATIO, global_config.WEIGHT_SUCC_RATIO,
                                           global_config.GRAPH_PRED_DEPTH, global_config.GRAPH_SUCC_DEPTH,
                                           global_config.DEFAULT_KEYWORDS)
    try:
        for data in ds:
            vul_wfdg = gen_wfdg.gen_WFDG_by_json(data['vul_wfdg'])
            if not vul_wfdg:
                return
            fixed_wfdg = gen_wfdg.gen_WFDG_by_json(data['fixed_wfdg'])
            if not fixed_wfdg:
                return
            vul = {
                'CVE_id': data['CVE_id'],
                'vul_wfdg': vul_wfdg,
                'fixed_wfdg': fixed_wfdg
            }
            dataset.append(vul)
            for key in data['keywords']:
                config_tran.add_keywords(key)
    except:
        perr('load dataset failed')
        return
    pinfo('load dataset successfully')

    start_time = my_time.cur_time()
    pinfo('start vulnerability detection at %s, detection path: %s, head path: %s'
          % (my_time.get_time_str(start_time), global_config.DETECT_PATH, global_config.HEAD_PATH))
    vul_result = detect.detect_by_cmp(global_config.DETECT_PATH, global_config.HEAD_PATH, dataset,
                                      config_tran=config_tran)
    end_time = my_time.cur_time()
    pinfo('end vulnerability detection at %s' % my_time.get_time_str(end_time))

    print('\nVulnerability Detection Result:')
    print('start time: %s    end time: %s    cost time: %s' %
          (my_time.get_time_str(start_time), my_time.get_time_str(end_time),
           my_time.get_time_interval(end_time - start_time)))
    print('per_cost_time: %s' % detect.get_cmp_time())
    if vul_result:
        print('found vulnerabilities:')
        print(' %-60s | %-30s | %-15s' % ('        file path', '       function name', 'CVE_id'))
        for res in vul_result:
            print(' %-60s   %-30s   %-15s' %
                  (res['file_path'], res['func_name'], res['CVE_id']))
        save_detect_result(vul_result)

    else:
        print('No vulnerabilities were found.')


def show_config():
    """输出系统的配置信息"""
    settings = dir(global_config)
    print('\t%-25s | %s' % ('Item', 'Value'))
    for setting in settings:
        if not setting.startswith('__') or not setting.endswith('__'):
            print('\t%-25s   %s' % (setting, getattr(global_config, setting)))


def set_config(config_item: str, new_value: str):
    """运行时修改系统的配置"""
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
    cmd_engine = CmdEngine('VulExplorer v1.0.0 - WFDG-based Vulnerability Detection System')

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
    cmd_engine.register_func(detect_vuls, [json_handler], 'detect', desc='start vulnerability detection')

    if len(sys.argv) > 1:
        cmd_engine.run_func(sys.argv[1:])
        return

    while True:
        ipt = input('>> ')
        args = ipt.split()
        cmd_engine.run_func(args)


if __name__ == '__main__':
    main()
