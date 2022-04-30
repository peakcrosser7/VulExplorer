import json
from typing import List, Set, Optional

from genWFDG import wfdg_generator
from genWFDG.wfdg_generator import WFDG
from utils.log import pinfo, perr

DEBUG = True


def gen_WFDGs_by_generator(filepath: str, header_list: List[str], dest_func: str = "", not_use_sensitive=False,
                           sensitive_line: int = 0, keywords: Set[str] = None) -> list:
    if DEBUG:
        pinfo('generate WFDGs from <%s>' % filepath)

    config = wfdg_generator.Configuration()
    if keywords:
        config.add_keywords(keywords)
    config.specify_func(dest_func, sensitive_line, not_use_sensitive)
    return wfdg_generator.gen_WFDGs([filepath], config, header_list)


def gen_WFDG_by_json(json_str: str) -> Optional[WFDG]:
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
