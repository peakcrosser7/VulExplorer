P_ERROR = 'ERROR'
P_WARNING = 'WARN'
P_DEBUG = 'DEBUG'
P_INFO = 'INFO '


def plog(p_type: str, args, kwargs):
    print('[ %-5s] ' % p_type, end='')
    print(*args, **kwargs)


def perr(*args, **kwargs):
    plog(P_ERROR, args, kwargs)


def pwarn(*args, **kwargs):
    plog(P_WARNING, args, kwargs)


def pdebug(*args, **kwargs):
    plog(P_DEBUG, args, kwargs)


def pinfo(*args, **kwargs):
    plog(P_INFO, args, kwargs)
