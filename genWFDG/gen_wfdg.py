import json
from typing import List, Optional

from genWFDG.wfdg_generator import WFDG

from genWFDG import config_trans
from genWFDG import wfdg_generator
from utils.log import pinfo, perr

DEBUG = True


def gen_WFDGs_by_generator(filepath: str, header_list: List[str], dest_func: str = "", not_use_sensitive=False,
                           sensitive_line: int = 0, config_tran: config_trans.ConfigTrans = None) -> list:
    """
    利用WFDG生成模块生成WFDG
    :param filepath: 源文件路径
    :param header_list: 头文件列表
    :param dest_func: 目标函数
    :param not_use_sensitive: 是否使用敏感行
    :param sensitive_line: 敏感行号
    :param config_tran: 传递的配置信息
    :return: 生成的WFDG列表
    """
    if DEBUG:
        pinfo('generate WFDGs from <%s>' % filepath)

    config = wfdg_generator.Configuration()
    if config_tran:
        config.weight_pred_ratio = config_tran.weight_pred_ratio
        config.weight_succ_ratio = config_tran.weight_pred_ratio
        config.graph_pred_depth = config_tran.graph_pred_depth
        config.graph_succ_depth = config_tran.graph_succ_depth
        config.key_words = config_tran.keywords
    config.specify_func(dest_func, sensitive_line, not_use_sensitive)
    return wfdg_generator.gen_WFDGs([filepath], config, header_list)


def gen_WFDG_by_json(json_str: str) -> Optional[WFDG]:
    """由JSON字符串生成WFDG"""
    try:
        json_obj = json.loads(json_str)
    except:
        perr('load WFDG from json failed')
        return None
    try:
        wfdg = WFDG(json_obj['funcName'], json_obj['rootLine'])
        for i, n in json_obj['nodes'].items():
            node = WFDG.WFDGNode()
            node.id = n['id']
            node.weight = n['weight']
            node.stmt_vec = n['stmtVec']
            wfdg.add_node(node.id, node)
        wfdg.set_all_edges(json_obj['allEdges'])
        return wfdg
    except:
        perr('generate WFDG from json failed')
        return None
