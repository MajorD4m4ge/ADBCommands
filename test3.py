import base64
import datetime
import argparse
import sys

from Crypto.Cipher import AES



# secret = 'intrepidlearner1'


def pkcs5_pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)


def encrypt(value, secret):
    error = False
    errortext = ''
    ciphertext = ''
    try:
        cipher = AES.new(secret)
        value = pkcs5_pad(value)
        ciphertext = base64.b64encode(cipher.encrypt(value))
    except ValueError:
        errortext = 'Error: Incorrect key length.'
        error = True
    finally:
        return ciphertext, error, errortext


def Header():
    print('')
    print('+--------------------------------------------------------------------------+')
    print('|Lession 6 - Learner                                                       |')
    print('+---------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                       |')
    print('+--------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+--------------------------------------------------------------------------+')


def Failed(error):
    print('  * ' + str(error))
    print('+--------------------------------------------------------------------------+')
    print('| Failed.                                                                  |')
    print('+--------------------------------------------------------------------------+')
    sys.exit(1)


def Completed():
    print('| [*] Completed.                                                           |')
    print('+--------------------------------------------------------------------------+')


def main(argv):
    #try:
    parser = argparse.ArgumentParser(description="A decryption program to help with lesson 6 in Learner.",
                                     add_help=True)
    parser.add_argument('-k', '--secretkey', help='The key needed to crypt.', required=False)
    parser.add_argument('-c', '--challenge', help='The challenge phone number generated by the application.',
                        required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    if args.secretkey:
        secretkey = args.secretkey
    else:
        secretkey = raw_input('Please enter in the encryption key: ')
    if args.challenge:
        challenge = args.challenge
    else:
        challenge = raw_input('Please enter the challenge phone number: ')
    Header()
    encoded, error, value = encrypt(challenge, secretkey)
    if not error:
        print('|                                                                          |')
        print('| [>] Challenge Phone:\t' + challenge.ljust(51, ' ') + '|')
        print('| [>] Encryption Key:\t' + secretkey.ljust(51, ' ') + '|')
        print('| [*] Encoded Value:\t' + encoded.ljust(51, ' ') + '|')
        print('+--------------------------------------------------------------------------+')
    else:
        Failed(value)
    Completed()


main(sys.argv[1:])

