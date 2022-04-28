from utils.cmd_engine import CmdEngine


def tester(s: int, n: int):
    for i in range(s, n):
        print(i)


def main():
    cmd_engine = CmdEngine('VulExplorer')
    cmd_engine.register_func(tester, [int, int], 'test', desc='run test')
    while True:
        ipt = input('>> ')
        cmd_engine.run_func(ipt)


if __name__ == '__main__':
    main()
