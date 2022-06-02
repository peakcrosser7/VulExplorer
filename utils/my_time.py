## 通用时间函数

import time


def cur_time() -> float:
    return time.time()


def get_time_str(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def get_time_interval(timestamp: float):
    m, s = divmod(timestamp, 60)
    h, m = divmod(m, 60)
    return '%02d:%02d:%02d' % (h, m, s)
