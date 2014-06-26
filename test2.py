# import sys
# import subprocess
#
#
# def ListProc():
# netstat = []
#     print('Entering List')
#     p = subprocess.check_output('adb shell cat /proc/net/tcp')
#     print(p)
#     return netstat
#
#
# def main(argv):
#     p = ListProc()
#     print(p)
#
#
# if __name__ == '__main__':
#     main(sys.argv[1:])

import base64
import binascii

from Crypto.Cipher import AES


def decrypt(input):
    # the block size for the cipher object; must be 16, 24, or 32 for AES
    BLOCK_SIZE = 32
    MODE = AES.MODE.ECB

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    # generate a random secret key
    # secret = os.urandom(BLOCK_SIZE)

    # create a cipher object using the random secret
    cipher = AES.new()

    # encode a string
    #encoded = EncodeAES(cipher, 'password')
    #print 'Encrypted string:', encoded

    # decode the encoded string
    decoded = DecodeAES()
    #print 'Decrypted string:', decoded
    return decoded


def dec(datainput):
    # print 'here'
    IV_SIZE = 16
    BLOCK_SIZE = 16
    data = '2cc538d4a8f98f2ee96a3369041f53e8'
    hexdata = '0123456789ABCDEF'
    key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    key = '0000000000000000'
    k1 = bytearray(key)
    b = bytearray(data)
    ciphertext = binascii.unhexlify(b)
    ciphertext = base64.b64decode(data)

    decobj = AES.new(key, AES.MODE_ECB)
    plaintext = decobj.decrypt(ciphertext)

    # Resulting plaintext
    print plaintext


def main(argv):
    # global debug
    # parser = argparse.ArgumentParser(description="Decode Ashley Madison.",
    # add_help=True)
    # parser.add_argument('-i', '--input', help='The hash from the hushed sqlite db.', required=False)
    # parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    # args = parser.parse_args()
    # if args.input:
    #     inputtext = args.input
    # else:
    #     inputtext = input("Please enter hash: ")
    dec('1')


main(sys.argv[1:])


#!/usr/bin/env python

import re
import sys


def print_memory_of_pid(pid, only_writable=True):
    """
    Run as root, take an integer PID and return the contents of memory to STDOUT
    """
    memory_permissions = 'rw' if only_writable else 'r'
    sys.stderr.write("PID = %d" % pid)
    with open("/proc/%d/maps" % pid, 'r') as maps_file:
        with open("/proc/%d/mem" % pid, 'r', 0) as mem_file:
            for line in maps_file.readlines():  # for each mapped region
                m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r][-w])', line)
                if m.group(3) == memory_permissions:
                    sys.stderr.write("\nOK : \n" + line + "\n")
                    start = 0L
                    end = 0L
                    start = long(m.group(1), 16)
                    if start > 0xFFFFFFFFFFFF:
                        continue
                    end = int(m.group(2), 16)
                    sys.stderr.write("start = " + str(start) + "\n" + "End = " + str(end) + "\n")
                    mem_file.seek()  # seek to region start
                    chunk = mem_file.read(end - start)  # read region contents
                    print chunk,  # dump contents to standard output
                else:
                    sys.stderr.write("\nPASS : \n" + line + "\n")


if __name__ == '__main__':  # Execute this code when run from the commandline.
    try:
        assert len(sys.argv) == 2, "Provide exactly 1 PID (process ID)"
        pid = int(sys.argv[1])
        print_memory_of_pid(pid)
    except (AssertionError, ValueError) as e:
        print "Please provide 1 PID as a commandline argument."
        print "You entered: %s" % ' '.join(sys.argv)
        raise e