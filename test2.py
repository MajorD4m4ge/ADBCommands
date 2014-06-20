import sys
import subprocess


def ListProc():
    netstat = []
    print('Entering List')
    p = subprocess.check_output('adb shell cat /proc/net/tcp')
    print(p)
    return netstat


def main(argv):
    p = ListProc()
    print(p)


if __name__ == '__main__':
    main(sys.argv[1:])