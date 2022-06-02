from typing import Set


class ConfigTrans:
    """配置信息传递类"""
    def __init__(self, weight_pred_ratio: float, weight_succ_ratio: float,
                 graph_pred_depth: int, graph_succ_depth: int, keywords: Set[str]):
        self.weight_pred_ratio = weight_pred_ratio
        self.weight_succ_ratio = weight_succ_ratio
        self.graph_pred_depth = graph_pred_depth
        self.graph_succ_depth = graph_succ_depth
        self.keywords = set(keywords)

    def add_keywords(self, keyword: str):
        self.keywords.add(keyword)
