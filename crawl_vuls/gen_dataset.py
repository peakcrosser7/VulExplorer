import json
import os

from crawl_vuls import config
from dataset_handler.handler import DataHandlerFactory
from genWFDG import gen_wfdg

g_dataset_dir = '../dataset/'
g_dataset_file_name = 'vul_data.json'

g_header_dir = '/home/hhy/vd_ipt/openssl/include'
g_app_root_dir = '/home/hhy/vd_ipt/openssl/'

g_header_list = gen_wfdg.get_header_dirs(g_header_dir)
g_header_list.extend(gen_wfdg.g_header_dirs)


def gen_vul_WFDG(vul_info: dict) -> dict:
    file_name = vul_info['file_paths'][0].split('/')[-1]
    if not gen_wfdg.correct_file_types(file_name):
        return {}

    header_list = []
    header_list.extend(g_header_list)
    dir_path = os.path.join(g_app_root_dir, vul_info['file_paths'][0].rstrip(file_name))
    print(dir_path)
    header_list.extend(gen_wfdg.get_local_header_dirs(dir_path))

    vul_func = vul_info['vul_func'][0]
    dir_path = os.path.join(config.CODE_FILE_STORE_DIR, vul_info['CVE_id'])

    filepath = os.path.join(dir_path, 'vul#' + file_name)
    print(filepath, header_list, vul_func, vul_info['sensitive_line'])
    wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
                                            sensitive_line=vul_info['sensitive_line'])
    vul_info['vul_wfdg'] = wfdgs[0].to_json()

    wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
                                            not_use_sensitive=True)
    vul_info['vul_wfdg_no_sen'] = wfdgs[0].to_json()

    filepath = os.path.join(dir_path, 'fixed#' + file_name)
    wfdgs = gen_wfdg.gen_WFDGs_by_generator(filepath, header_list, dest_func=vul_func,
                                            not_use_sensitive=True)
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
            print('open VUL_LIST_FILE:% failed' % vul_list_path)

    json_handler = DataHandlerFactory.create_handler(DataHandlerFactory.JSON_TYPE)
    json_handler.set_file_path(g_dataset_dir, g_dataset_file_name)
    for vul_info in vul_json:
        if vul_info['is_manual'] == 1:
            vul = gen_vul_WFDG(vul_info)
            json_handler.add_to_dataset(
                vul['CVE_id'], vul['file_paths'], vul['vul_func'][0],
                vul['sensitive_line'], vul['keywords'],
                vul['vul_wfdg'], vul['vul_wfdg_no_sen'], vul['fixed_wfdg'],
                vul['affected_vers'], vul['fixed_vers'], vul['vul_type']
            )
    json_handler.finish_dataset()


if __name__ == '__main__':
    gen_dataset_WFDG()
