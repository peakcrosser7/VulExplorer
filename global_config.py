## 系统的全局配置

# 数据集目录
DATASET_DIR = './dataset/'
# 输出结果目录
OUTPUT_DIR = './output'

# 检测目录
DETECT_PATH = '/home/hhy/openssl-1.0.2/ssl/'
# 头文件目录
HEAD_PATH = '/home/hhy/openssl-1.0.2/'

# 默认的漏洞关键词列表
DEFAULT_KEYWORDS = {
    "USER_SET", "memcpy", "strcpy", "read", "free", "buf"
}
# 认定为漏洞的相似度阈值
VUL_THRESHOLD = 0.8
# 权重前驱衰减值
WEIGHT_PRED_RATIO = 0.85
# 权重后继衰减值
WEIGHT_SUCC_RATIO = 0.85
# 图前驱跟踪深度
GRAPH_PRED_DEPTH = 5
# 图后继跟踪深度
GRAPH_SUCC_DEPTH = 5
