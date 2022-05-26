import math
from typing import List

import lapjv
import numpy
from genWFDG.wfdg_generator import WFDG

USE_WEIGHT = True


def node_ecul_sim(v1, v2) -> float:
    # Use euclidean value to compute the similarity of two nodes
    v1 = numpy.array(v1)
    v2 = numpy.array(v2)
    v1_norm = numpy.linalg.norm(v1)  # sqrt(x_1^2+x_2^2+...+x_n^2)
    v2_norm = numpy.linalg.norm(v2)

    if v1_norm == 0 or v2_norm == 0:
        return 0.
    dis = numpy.linalg.norm(v1 - v2)
    # (1-dis)/sqrt(v1)*sqrt(v2)
    return 1.0 - float(dis) / (v1_norm * v2_norm)


def node_cos_sim(v1, v2) -> float:
    # Use cos value to compute the similarity of two nodes
    dot_product = 0.
    norm_a = 0.
    norm_b = 0.
    for a, b in zip(v1, v2):
        dot_product += a * b
        norm_a += a ** 2
        norm_b += b ** 2
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.
    else:
        return dot_product / ((norm_a * norm_b) ** 0.5)


def calc_node_cost(stmt_vec1: list, stmt_vec2: list) -> float:
    if not stmt_vec1 or not stmt_vec2:
        return 1.
    if stmt_vec1 == stmt_vec2:
        return 0.
    sim = (node_ecul_sim(stmt_vec1, stmt_vec2) + node_cos_sim(stmt_vec1, stmt_vec2)) / 2.
    return 1 - sim


def calc_edge_cost(edge_feat1, edge_feat2) -> float:
    return (calc_node_cost(edge_feat1[0], edge_feat2[0]) + calc_node_cost(edge_feat1[1], edge_feat2[1])) / 2


def get_edge_feat(g: WFDG, edge):
    return g.get_node(edge[0]).stmt_vec, g.get_node(edge[1]).stmt_vec


def get_edge_weight(g: WFDG, edge) -> float:
    return max(g.get_node(edge[0]).weight, g.get_node(edge[1]).weight)


def resolve_linear_assign(cost_matrix: List[List[float]]) -> float:
    r, c, _ = lapjv.lapjv(cost_matrix)
    cost = 0.
    for i in range(len(r)):
        cost += cost_matrix[r[i]][c[i]]
    return cost


def graph_node_distance(g1: WFDG, g2: WFDG) -> float:
    MAX_VALUE = 10000.
    min_len = min(g1.get_node_cnt(), g2.get_node_cnt())
    if min_len == 0:
        return MAX_VALUE
    matrix_len = max(g1.get_node_cnt(), g2.get_node_cnt())

    diff = float(min_len) / matrix_len
    if diff < 0.5:
        return MAX_VALUE

    cost_matrix = []
    if g2.get_node_cnt() == matrix_len:
        g1, g2 = g2, g1
    for node1 in g1.get_nodes().values():
        cost_list = []
        for node2 in g2.get_nodes().values():
            cost = calc_node_cost(node1.stmt_vec, node2.stmt_vec)
            if USE_WEIGHT:
                cost *= (node1.weight + node2.weight) / 2
            cost_list.append(cost)
        for i in range(matrix_len - min_len):
            cost = calc_node_cost(node1.stmt_vec, [])
            if USE_WEIGHT:
                cost *= (node1.weight + 1.) / 2
            cost_list.append(cost)
        cost_matrix.append(cost_list)
    if len(cost_matrix) == 0:
        return MAX_VALUE
    return resolve_linear_assign(cost_matrix)


def graph_edge_distance(g1: WFDG, g2: WFDG) -> float:
    MAX_VALUE = 100.

    min_len = min(g1.get_all_edge_cnt(), g2.get_all_edge_cnt())
    if min_len == 0:
        return 0.
    matrix_len = max(g1.get_all_edge_cnt(), g2.get_all_edge_cnt())

    diff = float(min_len) / matrix_len
    if diff < 0.5:
        return MAX_VALUE

    cost_matrix = []
    if g2.get_all_edge_cnt() == matrix_len:
        g1, g2 = g2, g1
    for edge1 in g1.get_all_edges():
        cost_list = []
        edge1_feat = get_edge_feat(g1, edge1)
        edge1_weight = 0.
        if USE_WEIGHT:
            edge1_weight = get_edge_weight(g1, edge1)
        for edge2 in g2.get_all_edges():
            edge2_feat = get_edge_feat(g2, edge2)
            cost = calc_edge_cost(edge1_feat, edge2_feat)
            if USE_WEIGHT:
                edge2_weight = get_edge_weight(g2, edge2)
                cost *= (edge1_weight + edge2_weight) / 2
            cost_list.append(cost)
        for i in range(matrix_len - min_len):
            cost_list.append(0)
        cost_matrix.append(cost_list)
    return resolve_linear_assign(cost_matrix)


def weight_similarity(node_cnt1: int, node_cnt2: int, node_dis: float, edge_dis: float):
    feat_dis = (node_dis + math.sqrt(edge_dis)) / (node_cnt1 + node_cnt2)
    size_dis = abs(float(node_cnt1 - node_cnt2)) / (node_cnt1 + node_cnt2)
    alpha = 1.15
    beta = 0.05
    dis = feat_dis * alpha + size_dis * beta
    sim = 1 - dis
    return sim if sim > 0 else 0


def compare_wfdg(g1: WFDG, g2: WFDG) -> float:
    node_cnt1 = g1.get_node_cnt()
    node_cnt2 = g2.get_node_cnt()
    if node_cnt1 == 0 or node_cnt2 == 0:
        return 0.

    if max(node_cnt1, node_cnt2) > 3 * min(node_cnt1, node_cnt2):
        return 0.

    node_dis = graph_node_distance(g1, g2)
    edge_dis = graph_edge_distance(g1, g2)
    sim = weight_similarity(g1.get_node_cnt(), g2.get_node_cnt(), node_dis, edge_dis)
    return round(sim, 3)
