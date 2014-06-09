__author__ = 'khanta'

import argparse


def main(argv):
    global debug
    scan = False
    parser = argparse.ArgumentParser(description="A program to pull all apks off via the Android Debug Bridge.",
                                     add_help=True)
    parser.add_argument('-o', '--output', help='The output path to write the apk files to.', required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('-s', '--scan', help='The level of debugging.', action='store_true', required=False)
    parser.add_argument('-l', '--list', help='The level of debugging.', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()


main(sys.argv[1:])