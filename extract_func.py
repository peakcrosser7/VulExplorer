import os.path
import re
import subprocess
import sys
import time
from typing import List

DEBUG = 1

FILE_TYPES = ['.c', '.c#vul', '.c#fixed']

g_header_dirs = []

g_inline_funcs = []


def correct_file_types(filename: str) -> bool:
    """判断文件类型是否为c/cpp"""
    ret = os.path.splitext(filename)
    return len(ret) != 0 and ret[1] in FILE_TYPES


def get_header_dirs(header_dir: str) -> List[str]:
    header_dirs = [header_dir]
    for dirpath, dirnames, _ in os.walk(header_dir):
        for dirname in dirnames:
            header_dirs.append(os.path.join(dirpath, dirname))
    return header_dirs


def set_global_header_dirs():
    global g_header_dirs
    g_header_dirs = get_header_dirs(g_header_dir)


def get_local_header_dirs(dirpath: str):
    header_dir = os.path.join(dirpath, 'include')
    if not os.path.exists(header_dir):
        return []
    return get_header_dirs(header_dir)


def get_ast(filepath: str) -> List[str]:
    include_str = ''
    for header in g_header_dirs:
        include_str += ' -I %s' % header
    filename = filepath.split('/')[-1].strip()
    dirpath = filepath.rstrip('/' + filename)
    for header in get_local_header_dirs(dirpath):
        include_str += ' -I %s' % header

    cmd = 'clang -Xclang -ast-dump -fsyntax-only -fno-color-diagnostics %s %s' % (filepath, include_str)

    stats, output = subprocess.getstatusoutput(cmd)
    ast_lines = output.split('\n')

    if stats != 0 and 'file not found' in output:
        print('<%s> get AST error:')
        for line in ast_lines:
            if 'file not found' in line:
                print(line)
    return ast_lines


def get_funcs_info(filepath, ast_lines):
    func_list = []
    for line in ast_lines:
        if "FunctionDecl" in line:  # 查找函数定义
            func_list.append(line.strip())

    result_list = []
    for func_str in func_list:
        if func_str.endswith('extern'):
            continue
        info = re.findall(r"(<.*,\sline.*>\s[a-zA-z0-9:]*\s[a-zA-Z0-9_]*)", func_str)
        if not info:
            continue
        func_infos = info[0].split(' ')
        func_name = func_infos[-1].strip()
        if func_name in ['used', 'invalid']:
            info = re.findall(r"(<.*,\sline.*>\s[a-zA-z0-9:]*\s%s\s[a-zA-Z0-9_]*)" % func_name, func_str)
            func_name = info[0].split(' ')[-1]

        if func_infos[0].split(':')[0].endswith('.h'):
            continue

        if func_infos[0][1:4] == 'col':  # TODO: some functions are 'col:1'
            print(filepath, '|', func_str)
            continue

        start_line = int((func_infos[0]).split(':')[1])
        end_line = int((func_infos[1]).split(':')[1])

        cmd = 'grep -n %s %s | grep %d' % (func_name, filepath, start_line)
        ret = subprocess.getstatusoutput(cmd)
        if ret[0] != 0:
            cmd = 'grep -n %s %s | grep %d' % (func_name, filepath, start_line + 1)
            # Case: func_type and func_name are in different lines
            ret = subprocess.getstatusoutput(cmd)
            if ret[0] != 0:
                continue

        if DEBUG:
            print(filepath, func_name, start_line, end_line)
        result_list.append([func_name, start_line, end_line])

    return result_list


def extract_funcs_from_file(filepath: str):
    print('Extract funcs from <%s>' % filepath)
    filename = filepath.split('/')[-1].strip()
    ast_lines = get_ast(filepath)
    funcs_info = get_funcs_info(filepath, ast_lines)

    for func_info in funcs_info:
        start_line = func_info[1]
        end_line = func_info[2]
        output_file = os.path.join(g_output_folder, filename + '#' + func_info[0] + '#' + str(start_line) + '.c')
        with open(output_file, 'w') as wf:
            with open(filepath, 'r') as rf:
                i = 0
                for line in rf:
                    i += 1
                    if i > end_line:
                        break
                    if i >= start_line:
                        wf.write(line)




def extract_funcs():
    if not os.path.exists(g_output_folder):
        os.makedirs(g_output_folder)

    set_global_header_dirs()

    if not os.path.isdir(g_input_dir):
        extract_funcs_from_file(g_input_dir)
        return

    for dirpath, _, filenames in os.walk(g_input_dir):
        for filename in filenames:
            if not correct_file_types(filename):
                continue
            extract_funcs_from_file(os.path.join(dirpath, filename))


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("extract_func.py <input_dir> <output_folder> <header_dir>\n")
        exit(-1)

    g_input_dir = sys.argv[1]
    g_output_folder = sys.argv[2]
    g_header_dir = sys.argv[3]

    if not os.path.exists(g_input_dir) or not os.path.exists(g_header_dir):
        exit(-1)

    s = time.time()
    print("start time: ", s)

    extract_funcs()

    s = time.time() - s
    m, s = divmod(s, 60)
    h, m = divmod(m, 60)
    print("cost time: %02d:%02d:%02d" % (h, m, s))
