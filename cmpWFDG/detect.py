import os.path
import sys
from typing import List, Set

import global_config
from cmpWFDG import cmp_wfdg
from genWFDG import gen_wfdg
from utils.log import *

DEBUG = True

g_header_dirs = ['-w', '-I/usr/local/lib/clang/9.0.0/include']


def correct_file_types(filename: str) -> bool:
    """判断文件类型是否为c/cpp"""
    return filename.endswith('.c')


def gen_include_info(head_path):
    return '-I' + head_path


def get_header_dirs(dir_path: str, head_path: str) -> List[str]:
    header_list = [gen_include_info(dir_path)]
    header_dir = os.path.join(dir_path, 'include')
    if os.path.exists(header_dir):
        header_list.append(header_dir)
        for dirpath, dir_names, _ in os.walk(header_dir):
            for dirname in dir_names:
                header_list.append(gen_include_info(os.path.join(dirpath, dirname)))
    if head_path:
        head_path = head_path.rstrip('/')
        dir_path = dir_path.rstrip('/')
        tail = dir_path.split('/')[-1]
        dir_path = dir_path.rstrip('/' + tail)
        while dir_path != head_path:
            header_list.append(dir_path)
            tail = dir_path.split('/')[-1]
            dir_path = dir_path.rstrip('/' + tail)
    return header_list


def cmp_with_dataset(file_path: str, wfdgs: list, dataset: list):
    vul_result = []
    pinfo('compare <%s> with vul dataset...' % file_path)
    for wfdg in wfdgs:
        for vul_info in dataset:
            sim = cmp_wfdg.compare_wfdg(wfdg, vul_info['vul_wfdg'])
            if sim > global_config.VUL_THRESHOLD \
                    and sim > cmp_wfdg.compare_wfdg(wfdg, vul_info['fixed_wfdg']):
                vul = {
                    'CVE_id': vul_info['CVE_id'],
                    'file_path': file_path,
                    'func_name': wfdg.get_func_name()
                }
                vul_result.append(vul)
                pinfo('find vul(CVE_id: %s) in path:%s func:%s' %
                      (vul['CVE_id'], file_path, vul['func_name']))
    return vul_result


def detect_by_cmp(input_path: str, head_path: str, dataset: list, keywords: Set[str]):
    if not os.path.exists(input_path):
        perr('input path:%s does not exist' % input_path)
        return None
    if not os.path.exists(head_path):
        perr('root path:%s does not exist' % head_path)
        return None

    header_list = []
    header_list.extend(g_header_dirs)
    header_list.extend(get_header_dirs(head_path, ''))

    if os.path.isfile(input_path):
        if correct_file_types(input_path):
            filename = input_path.split('/')[-1].strip()
            dirpath = input_path.rstrip('/' + filename)
            header_list.extend(get_header_dirs(dirpath, head_path))
            wfdgs = gen_wfdg.gen_WFDGs_by_generator(input_path, header_list, keywords=keywords)
            return cmp_with_dataset(input_path, wfdgs, dataset)

    vul_result = []
    for dirpath, _, filenames in os.walk(input_path):
        tmp_header_list = []
        tmp_header_list.extend(header_list)
        tmp_header_list.extend(get_header_dirs(dirpath, head_path))
        for filename in filenames:
            if correct_file_types(filename):
                file_path = os.path.join(dirpath, filename)
                wfdgs = gen_wfdg.gen_WFDGs_by_generator(file_path, tmp_header_list,
                                                        keywords=keywords)
                vul_result.extend(cmp_with_dataset(file_path, wfdgs, dataset))
    return vul_result


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("python3 extract_func.py <input_dir> <output_folder> <header_dir>\n")
        exit(-1)
    g_input_dir = sys.argv[1]
    g_output_dir = sys.argv[2]
    g_header_dir = sys.argv[3]
