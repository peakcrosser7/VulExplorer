DATASET_DIR = './dataset/'
OUTPUT_DIR = './output'

DETECT_PATH = '/home/hhy/openssl-1.0.2/ssl/'
HEAD_PATH = '/home/hhy/openssl-1.0.2/'

DEFAULT_KEYWORDS = {
    "USER_SET", "memcpy", "strcpy", "read", "free", "buf"
}
VUL_THRESHOLD = 0.8
WEIGHT_PRED_RATIO = 0.85
WEIGHT_SUCC_RATIO = 0.85
GRAPH_PRED_DEPTH = 5
GRAPH_SUCC_DEPTH = 5
