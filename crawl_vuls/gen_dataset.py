import json
import os

import global_config
from crawl_vuls import config
from dataset_handler.handler import DataHandlerFactory
from genWFDG import gen_wfdg
from genWFDG import config_trans
from cmpWFDG import detect
from utils.log import perr

g_dataset_dir = '../dataset/'

g_header_dir = '/home/hhy/openssl-1.0.1a/'
g_app_root_dir = '/home/hhy/openssl-1.0.1a/'

g_header_list = ['-w', '-I/usr/local/lib/clang/9.0.0/include']
g_header_list.extend(detect.get_header_dirs(g_header_dir, ''))


def gen_vul_WFDG(vul_info: dict, config_tran: config_trans.ConfigTrans) -> dict:
    file_name = vul_info['file_paths'][0].split('/')[-1]
    if not detect.correct_file_types(file_name):
        return {}

    header_list = []
    header_list.extend(g_header_list)
    dir_path = os.path.join(g_app_root_dir, vul_info['file_paths'][0].rstrip(file_name))
    # print(dir_path)
    header_list.extend(detect.get_header_dirs(dir_path, g_header_dir))

    vul_func = vul_info['vul_func'][0]
    dir_path = os.path.join(config.CODE_FILE_STORE_DIR, vul_info['CVE_id'])

    filepath = os.path.join(dir_path, 'vul#' + file_name)
    # print(filepath, header_list, vul_func, vul_info['sensitive_line'])
    wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
                                            sensitive_line=vul_info['sensitive_line'], config_tran=config_tran)
    vul_info['vul_wfdg'] = wfdgs[0].to_json()

    # wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
    #                                         not_use_sensitive=True)
    # vul_info['vul_wfdg_no_sen'] = wfdgs[0].to_json()
    vul_info['vul_wfdg_no_sen'] = ''

    filepath = os.path.join(dir_path, 'fixed#' + file_name)
    wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
                                            not_use_sensitive=True, config_tran=config_tran)
    vul_info['fixed_wfdg'] = wfdgs[0].to_json()
    return vul_info


def gen_dataset_WFDG():
    vul_json = []
    for i in [1, 2]:
        vul_list_path = os.path.join(config.DATASET_STORE_DIR, config.VUL_LIST_FILE_NAME + "_%s" % i + '.json')
        try:
            with open(vul_list_path, 'r') as rf:
                vul_json.extend(json.load(rf))
        except:
            perr('open VUL_LIST_FILE:% failed' % vul_list_path)

    config_tran = config_trans.ConfigTrans(global_config.WEIGHT_PRED_RATIO, global_config.WEIGHT_SUCC_RATIO,
                                           global_config.GRAPH_PRED_DEPTH, global_config.GRAPH_SUCC_DEPTH,
                                           global_config.DEFAULT_KEYWORDS)

    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    json_handler.set_dataset_dir(g_dataset_dir)
    for vul_info in vul_json:
        if vul_info['is_manual'] == 1:
            vul = gen_vul_WFDG(vul_info, config_tran)
            json_handler.add_to_dataset(
                vul['CVE_id'], vul['file_paths'], vul['vul_func'][0],
                vul['sensitive_line'], vul['keywords'],
                vul['vul_wfdg'],
                vul['vul_wfdg_no_sen'],
                vul['fixed_wfdg'],
                vul['affected_vers'], vul['fixed_vers'], vul['vul_type']
            )
    json_handler.finish_dataset()


if __name__ == '__main__':
    gen_dataset_WFDG()
