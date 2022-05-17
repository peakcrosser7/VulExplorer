import os.path
import time
from typing import List, Set

import global_config
from cmpWFDG import cmp_wfdg
from genWFDG import gen_wfdg
from utils import my_time
from utils.log import *

DEBUG = True

g_header_dirs = ['-w', '-I/usr/local/lib/clang/9.0.0/include']

g_cost_time = 0
g_wfdgs_cnt = 0


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
        if dir_path != head_path:
            tail = dir_path.split('/')[-1]
            dir_path = dir_path.rstrip('/' + tail)
            i = 0
            while dir_path != head_path and i < 5:
                header_list.append(dir_path)
                tail = dir_path.split('/')[-1]
                dir_path = dir_path.rstrip('/' + tail)
                i += 1
    return header_list


def cmp_with_dataset(file_path: str, wfdgs: list, dataset: list):
    global g_cost_time, g_wfdgs_cnt
    vul_result = []
    pinfo('compare <%s> with vul dataset...' % file_path)
    for vul_info in dataset:
        checked_funcs = set()
        for wfdg in wfdgs:
            if wfdg.get_func_name() in checked_funcs:
                continue
            s = time.time()
            sim = cmp_wfdg.compare_wfdg(wfdg, vul_info['vul_wfdg'])
            g_cost_time += time.time() - s
            g_wfdgs_cnt += 1
            if sim > global_config.VUL_THRESHOLD:
                s = time.time()
                p_sim = cmp_wfdg.compare_wfdg(wfdg, vul_info['fixed_wfdg'])
                g_cost_time += time.time() - s
                g_wfdgs_cnt += 1
                if sim > p_sim:
                    vul = {
                        'CVE_id': vul_info['CVE_id'],
                        'file_path': file_path,
                        'func_name': wfdg.get_func_name()
                    }
                    checked_funcs.add(wfdg.get_func_name())
                    vul_result.append(vul)
                    pinfo('find vul(CVE_id: %s) in path:%s func:%s' %
                          (vul['CVE_id'], file_path, vul['func_name']))
    return vul_result


def detect_by_cmp(input_path: str, head_path: str, dataset: list, keywords: Set[str] = None):
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
        # for h in tmp_header_list:
        #     print('--extra-arg="%s" ' % h, end='')
        for filename in filenames:
            if correct_file_types(filename):
                file_path = os.path.join(dirpath, filename)
                wfdgs = gen_wfdg.gen_WFDGs_by_generator(file_path, tmp_header_list,
                                                        keywords=keywords)
                vul_result.extend(cmp_with_dataset(file_path, wfdgs, dataset))
    return vul_result


def get_cmp_time() -> float:
    if g_wfdgs_cnt == 0:
        return -1.
    return float(g_cost_time) / g_wfdgs_cnt


if __name__ == '__main__':
    g_input_dir = global_config.DETECT_PATH
    g_header_dir = global_config.HEAD_PATH
    start_time = time.time()
    pinfo('start vulnerability detection at %s, detection path: %s, head path: %s'
          % (my_time.get_time_str(start_time), global_config.DETECT_PATH, global_config.HEAD_PATH))
    detect_by_cmp(g_input_dir, g_header_dir, [])
    end_time = time.time()
    pinfo('end vulnerability detection at %s' % my_time.get_time_str(end_time))
    print('start time: %s    end time: %s    cost time: %s' %
          (my_time.get_time_str(start_time), my_time.get_time_str(end_time),
           my_time.get_time_interval(end_time - start_time)))
