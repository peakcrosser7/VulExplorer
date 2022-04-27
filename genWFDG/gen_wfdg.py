import os.path
import sys
import time
from typing import List

from genWFDG import wfdg_generator

DEBUG = True

FILE_TYPE = '.c'

g_header_dirs = ['-w', '-I/usr/local/lib/clang/9.0.0/include']

g_total_wfdgs = 0


def correct_file_types(filename: str) -> bool:
    """判断文件类型是否为c/cpp"""
    ret = os.path.splitext(filename)
    return len(ret) != 0 and ret[1] == FILE_TYPE


def get_header_dirs(header_dir: str) -> List[str]:
    header_dirs = ['-I' + header_dir]
    for dirpath, dirnames, _ in os.walk(header_dir):
        for dirname in dirnames:
            header_dirs.append('-I' + os.path.join(dirpath, dirname))
    return header_dirs


def get_local_header_dirs(dirpath: str) -> List[str]:
    head_list = get_header_dirs(dirpath)
    header_dir = os.path.join(dirpath, 'include')
    if os.path.exists(header_dir):
        head_list.extend(get_header_dirs(header_dir))
    return head_list


def gen_WFDGs_by_generator(filepath: str, header_list: List[str], dest_func: str = "", not_use_sensitive=False,
                           sensitive_line: int = 0) -> list:
    if DEBUG:
        print('Generate WFDGs from <%s>' % filepath)

    config = wfdg_generator.Configuration()
    config.specify_func(dest_func, sensitive_line, not_use_sensitive)
    wfdgs = wfdg_generator.gen_WFDGs([filepath], config, header_list)
    num = len(wfdgs)
    global g_total_wfdgs
    g_total_wfdgs += num
    print(num)
    return wfdgs


def gen_all_WFDGs(input_dir: str, header_dir: str, output_dir: str):
    if not os.path.exists(input_dir) or not os.path.exists(header_dir):
        return
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    header_list = []
    header_list.extend(g_header_dirs)
    header_list.extend(get_header_dirs(header_dir))

    if not os.path.isdir(input_dir):
        if correct_file_types(input_dir):
            filename = input_dir.split('/')[-1].strip()
            dirpath = input_dir.rstrip('/' + filename)
            header_list.extend(get_local_header_dirs(dirpath))
            gen_WFDGs_by_generator(input_dir, header_list)
        return

    for dirpath, _, filenames in os.walk(input_dir):
        tmp_header_list = []
        tmp_header_list.extend(header_list)
        tmp_header_list.extend(get_local_header_dirs(dirpath))
        for filename in filenames:
            if correct_file_types(filename):
                gen_WFDGs_by_generator(os.path.join(dirpath, filename), tmp_header_list)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("python3 extract_func.py <input_dir> <output_folder> <header_dir>\n")
        exit(-1)
    g_input_dir = sys.argv[1]
    g_output_dir = sys.argv[2]
    g_header_dir = sys.argv[3]

    s = time.time()
    print("start time: ", s)

    gen_all_WFDGs(g_input_dir, g_header_dir, g_output_dir)

    s = time.time() - s
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    print("cost time: %02d:%02d:%02d" % (h, m, s))
    print("total WFDGs: ", g_total_wfdgs)
