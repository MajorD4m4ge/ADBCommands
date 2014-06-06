__author__ = 'khanta'

import sys
import hashlib
import os
import subprocess
import datetime
import argparse
import signal


def signal_handler(signal, frame):
    print('Ctrl+C pressed. Exiting.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def PullAPKs(applications, output):
    status = True
    error = ''
    try:
        for app in applications:
            p = subprocess.call('adb pull /data/app/' + app + ' ' + output, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    except:
        error = 'Error: Cannot copy APK files.'
        status = False
    finally:
        return status, error


def ListAPKs():
    status = True
    error = ''
    try:
        applications = []
        p = subprocess.Popen('adb shell ls /data/app', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            applications.append(line.decode("ASCII").rstrip())
            # retval = p.wait()
    except:
        error = 'Error: Cannot list APK files.'
        status = False
    finally:
        return status, error, applications


def GenerateHashAVD(applications):
    status = True
    error = ''
    temphashes = []
    applicationhashes = []
    try:
        for app in applications:
            p = subprocess.Popen('adb shell md5 /data/app/' + app, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                temphashes.append(line.decode("ASCII").rstrip())
        for items in temphashes:
            applicationhashes.extend(items.split())
    except:
        error = 'Error: Cannot calculate AVD APK file hashes.'
        status = False
    finally:
        return status, error, applicationhashes


def GenerateHashLocal(outputpath):
    status = True
    error = ''
    localapplicationhashes = []
    filenames = next(os.walk(outputpath))[2]
    for file in filenames:
        localapplicationhashes.append(Hasher(outputpath + '\\' + file, 'md5'))
        localapplicationhashes.append(file)
    return status, error, localapplicationhashes


def CompareHashes(applicationhashes, localapplicationhashes):
    status = True
    error = ''

    templist = []
    for item in applicationhashes:
        if '/data/app/' in item:
            temp = str(item).strip('/data/app/')
            templist.append(temp)
        else:
            templist.append(item)
    if templist == localapplicationhashes:
        return status, error
    else:
        error = 'Error: Hashes do not match.'
        return status, error


def Hasher(filename, hashtype):
    if hashtype == 'md5':
        md5 = hashlib.md5()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
                md5.update(chunk)
        return md5.hexdigest()


def Header(outputpath):
    print('')
    print('+--------------------------------------------------------------------------+')
    print('|APK File retriever.                                                       |')
    print('+---------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                       |')
    print('+--------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+--------------------------------------------------------------------------+')
    print('  Output Path:  ' + str(outputpath))
    print('+--------------------------------------------------------------------------+')


def List(outputpath):
    print('|List of Applications                                                      |')
    print('+--------------------------------------------------------------------------+')
    filenames = next(os.walk(outputpath))[2]
    for file in filenames:
        print('  App: ' + file + ' -- ' + Hasher(outputpath + '\\' + file, 'md5'))
    print('+--------------------------------------------------------------------------+')


def Failed(error):
    print('  * Error: ' + str(error))
    print('+--------------------------------------------------------------------------+')
    print('| Failed.                                                                  |')
    print('+--------------------------------------------------------------------------+')
    sys.exit(1)


def Completed():
    print('| [*] Completed.                                                           |')
    print('+--------------------------------------------------------------------------+')


def main(argv):
    parser = argparse.ArgumentParser(description="A program to pull all apks off via the Android Debug Bridge.",
                                     add_help=True)
    parser.add_argument('-o', '--output', help='The output path to write the apk files to.', required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    if args.output:
        outputpath = args.output
        if not os.path.isdir(outputpath):
            print('')
            print('Error: Directory --> ' + str(outputpath) + ' does not exist.')
            sys.exit(1)
    Header(outputpath)
    print('| [#] Listing APK Files.                                                   |')
    status, error, applications = ListAPKs()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                             |')
        Failed(error)
    print('| [#] Calculating AVD APK Hashes.                                          |')
    status, error, applicationhashes = GenerateHashAVD(applications)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                             |')
        Failed(error)
    print('| [#] Pulling APK Files.                                                   |')
    status, error = PullAPKs(applications, outputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                             |')
        Failed(error)
    print('| [#] Calculating Local APK Hashes.                                        |')
    status, error, localapplicationhashes = GenerateHashLocal(outputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                             |')
        Failed(error)
    print('| [#] Comparing APK Hashes.                                                |')
    status, error = CompareHashes(applicationhashes, localapplicationhashes)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                             |')
        Failed(error)
    if not error == "":
        Completed()
        List(outputpath)


main(sys.argv[1:])