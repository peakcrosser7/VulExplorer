import json
import os
from typing import Optional

import global_config
from cmpWFDG import detect
from crawl_vuls import config
from dataset_handler.handler import DataHandlerFactory
from genWFDG import config_trans
from genWFDG import gen_wfdg
from utils.log import perr

g_dataset_dir = '../dataset/'

g_header_dir = '/home/hhy/openssl-1.0.1a/'
g_app_root_dir = '/home/hhy/openssl-1.0.1a/'

g_header_list = ['-w', '-I/usr/local/lib/clang/9.0.0/include']
g_header_list.extend(detect.get_header_dirs(g_header_dir, ''))


def gen_vul_WFDG(vul_json: dict, config_tran: config_trans.ConfigTrans) -> Optional[dict]:
    header_list = []
    header_list.extend(g_header_list)
    vul_json['vul_wfdg'] = []
    vul_json['vul_wfdg_no_sen'] = []
    vul_json['fixed_wfdg'] = []
    for vul_info in vul_json['vul_info']:
        file_path = vul_info['file_path']
        file_name = file_path.split('/')[-1]
        if not detect.correct_file_types(file_path):
            continue
        tmp_headers = []
        tmp_headers.extend(header_list)
        dir_path = os.path.join(g_app_root_dir, file_path.rstrip(file_name))
        tmp_headers.extend(detect.get_header_dirs(dir_path, g_header_dir))

        vul_file_path = os.path.join(g_app_root_dir, file_path)
        fixed_file_path = os.path.join(g_app_root_dir, file_path)
        # dataset_dir = os.path.join(config.CODE_FILE_STORE_DIR, vul_json['CVE_id'])
        # vul_file_path = os.path.join(dataset_dir, 'vul#' + file_name)
        # fixed_file_path = os.path.join(dataset_dir, 'fixed#' + file_name)

        for func in vul_info['funcs']:
            wfdgs = gen_wfdg.gen_WFDGs_by_generator(vul_file_path, tmp_headers, dest_func=func[0],
                                                    sensitive_line=func[1], config_tran=config_tran)
            if not wfdgs:
                continue
            vul_json['vul_wfdg'].append(wfdgs[0].to_json())

            # wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
            #                                         not_use_sensitive=True)
            # vul_json['vul_wfdg_no_sen'] = wfdgs[0].to_json()

            wfdgs = gen_wfdg.gen_WFDGs_by_generator(fixed_file_path, tmp_headers, dest_func=func[0],
                                                    not_use_sensitive=True, config_tran=config_tran)
            vul_json['fixed_wfdg'].append(wfdgs[0].to_json())

    if len(vul_json['vul_wfdg']) == 0 or len(vul_json['fixed_wfdg']) == 0:
        return None

    return vul_json


def gen_dataset_WFDG():
    vul_json_list = []
    for i in [1]:
        vul_list_path = os.path.join(config.DATASET_STORE_DIR, config.VUL_LIST_FILE_NAME + "_%s" % i + '.json')
        try:
            with open(vul_list_path, 'r') as rf:
                vul_json_list.extend(json.load(rf))
        except:
            perr('open VUL_LIST_FILE:% failed' % vul_list_path)

    config_tran = config_trans.ConfigTrans(global_config.WEIGHT_PRED_RATIO, global_config.WEIGHT_SUCC_RATIO,
                                           global_config.GRAPH_PRED_DEPTH, global_config.GRAPH_SUCC_DEPTH,
                                           global_config.DEFAULT_KEYWORDS)

    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    json_handler.set_dataset_dir(g_dataset_dir)
    for vul_json in vul_json_list:
        if vul_json['is_manual'] == 1:
            vul = gen_vul_WFDG(vul_json, config_tran)
            if vul:
                json_handler.add_to_dataset(
                    vul['CVE_id'], vul['vul_info'], vul['keywords'],
                    vul['vul_wfdg'],
                    vul['vul_wfdg_no_sen'],
                    vul['fixed_wfdg'],
                    vul['affected_vers'], vul['fixed_vers'], vul['vul_type']
                )
    json_handler.finish_dataset()


if __name__ == '__main__':
    gen_dataset_WFDG()
