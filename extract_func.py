import os.path
import re
import subprocess
import sys
import time
from typing import List

import func_extractor

DEBUG = True

FILE_TYPES = ['.c', '.c#vul', '.c#fixed']

g_header_dirs = ['-I/usr/local/lib/clang/9.0.0/include']


def correct_file_types(filename: str) -> bool:
    """判断文件类型是否为c/cpp"""
    ret = os.path.splitext(filename)
    return len(ret) != 0 and ret[1] in FILE_TYPES


def get_header_dirs(header_dir: str) -> List[str]:
    header_dirs = ['-I' + header_dir]
    for dirpath, dirnames, _ in os.walk(header_dir):
        for dirname in dirnames:
            header_dirs.append('-I' + os.path.join(dirpath, dirname))
    return header_dirs


def set_global_header_dirs(header_dir):
    global g_header_dirs
    g_header_dirs.extend(get_header_dirs(header_dir))


def get_local_header_dirs(dirpath: str):
    header_dir = os.path.join(dirpath, 'include')
    if not os.path.exists(header_dir):
        return []
    return get_header_dirs(header_dir)


def extract_func_from_file(input_file: str, output_file: str, start_line: int, end_line: int):
    with open(output_file, 'w') as wf:
        with open(input_file, 'r') as rf:
            i = 0
            for line in rf:
                i += 1
                if i > end_line:
                    break
                if i >= start_line:
                    wf.write(line)


def extract_funcs_with_tool(filepath: str, output_dir: str):
    if not correct_file_types(filepath):
        return
    if DEBUG:
        print('Extract funcs from <%s>' % filepath)
    filename = filepath.split('/')[-1].strip()
    # ast_lines = get_ast(filepath)
    # funcs_info = get_funcs_info(filepath, ast_lines)
    dirpath = filepath.rstrip('/' + filename)
    header_list = ['-w']
    header_list.extend(g_header_dirs)
    header_list.extend(get_local_header_dirs(dirpath))
    funcs_info = func_extractor.extract_func_decl([filepath], header_list)
    for func_info in funcs_info:
        start_line = func_info.get_start_line()
        end_line = func_info.get_end_line()
        output_file = os.path.join(output_dir,
                                   filename + '#' + func_info.get_func_name() + '#' + str(start_line) + '.c')
        if DEBUG:
            print(filepath, func_info.get_func_name(), start_line, end_line)
        extract_func_from_file(filepath, output_file, start_line, end_line)


def extract_funcs(input_dir: str, output_dir: str, header_dir: str):
    if not os.path.exists(input_dir) or not os.path.exists(header_dir):
        return
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    set_global_header_dirs(header_dir)

    if not os.path.isdir(input_dir):
        extract_funcs_with_tool(input_dir, output_dir)
        return

    for dirpath, _, filenames in os.walk(input_dir):
        for filename in filenames:
            extract_funcs_with_tool(os.path.join(dirpath, filename), output_dir)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("python3 extract_func.py <input_dir> <output_folder> <header_dir>\n")
        exit(-1)
    g_input_dir = sys.argv[1]
    g_output_dir = sys.argv[2]
    g_header_dir = sys.argv[3]

    s = time.time()
    print("start time: ", s)

    extract_funcs(g_input_dir, g_output_dir, g_header_dir)

    s = time.time() - s
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    print("cost time: %02d:%02d:%02d" % (h, m, s))
