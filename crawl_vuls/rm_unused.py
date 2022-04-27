import os
import shutil

import json

from crawl_vuls import config


def remove_unused_codes():
    vul_json = []
    for i in ['_1', '_2']:
        vul_list_path = os.path.join(config.DATASET_STORE_DIR, config.VUL_LIST_FILE_NAME + i + '.json')
        try:
            with open(vul_list_path, 'r') as rf:
                vul_json.extend(json.load(rf))
        except:
            print('open VUL_LIST_FILE:% failed' % vul_list_path)

    used_dirs = set()
    for vul_info in vul_json:
        if vul_info['is_manual'] == 1:
            used_dirs.add(vul_info['CVE_id'])

    root_path = os.path.join('./', config.CODE_FILE_STORE_DIR)
    try:
        dirs = os.listdir(root_path)
    except FileNotFoundError as e:
        print(e)
        return

    for dir_name in dirs:
        dir_path = os.path.join(root_path, dir_name)
        if os.path.isdir(dir_path):
            if dir_name not in used_dirs:
                print('remove path: %s' % dir_path)
                shutil.rmtree(dir_path)


if __name__ == '__main__':
    remove_unused_codes()
