__author__ = 'khanta'
# MY Api Key for VirusTotal - bd527801758bee752fe0aef5a52e87f5020eb1359f0b3b0e458b596373db1ce0

import sys
import hashlib
import os
import subprocess
import datetime
import argparse
import signal

debug = 0

def signal_handler(signal, frame):
    print('Ctrl+C pressed. Exiting.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def DeviceCheck():
    status = True
    error = ''

    try:
        if debug >= 1:
            print('Entering DeviceCheck')
        templist = []
        if debug >= 2:
            print('\tLaunching command "adb devices"')
        p = subprocess.Popen('adb devices', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            if debug >= 3:
                print('\tDevices: ' + str(line))
            templist.append(line)
        if debug >= 3:
            print('\tTotal count of items: ' + str(len(templist)))
        if (len(templist)) >= 3:
            if debug >= 2:
                print('\tDevice attached.')
        else:
            error = True
            status = 'Error: Device not attached.'
    except:
        error = False
        status = 'Error: Device not detected.'
    finally:
        return status, error


def ListAPKs():
    status = True
    error = ''
    applications = []

    try:
        if debug >= 1:
            print('Entering ListAPKs')
        if debug >= 2:
            print('\tLaunching command "adb shell ls /data/app"')
        p = subprocess.Popen('adb shell ls /data/app', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            if debug >= 3:
                print('\tApplications on AVD: ' + str(line.decode("ASCII").rstrip()))
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
        if debug >= 1:
            print('Entering GenerateHashAVD')
        if debug >= 2:
            print('\tLaunching command "adb shell md5 /data/app/"')
        for app in applications:
            p = subprocess.Popen('adb shell md5 /data/app/' + app, shell=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            for line in p.stdout.readlines():
                temphashes.append(line.decode("ASCII").rstrip())
                if debug >= 3:
                    print('\tHashes generated on AVD: ' + str(line.decode("ASCII").rstrip()))
        for items in temphashes:
            applicationhashes.extend(items.split())
    except:
        error = 'Error: Cannot calculate AVD APK file hashes.'
        status = False
    finally:
        return status, error, applicationhashes


def PullAPKs(applications, outputpath):
    status = True
    error = ''
    try:
        if debug >= 1:
            print('Entering PullAPKs')
        if debug >= 2:
            print('\tLaunching command "adb pull /data/app/" for each application.')
        if debug >= 3:
            print('\tApplications passed in: ' + str(applications))
            print('\tOutput path passed in: ' + str(outputpath))
        for app in applications:
            p = subprocess.call('adb pull /data/app/' + app + ' ' + outputpath, shell=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
    except:
        error = 'Error: Cannot copy APK files.'
        status = False
    finally:
        return status, error


def GenerateHashLocal(outputpath):
    status = True
    error = ''
    localapplicationhashes = []
    try:
        if debug >= 1:
            print('Entering GenerateHashLocal')
        if debug >= 2:
            print('\tOutput path passed in: ' + str(outputpath))
        filenames = next(os.walk(outputpath))[2]
        if debug >= 3:
            print('\tFilenames in local directory: ' + str(filenames))
        for file in filenames:
            localapplicationhashes.append(Hasher(outputpath + '\\' + file, 'md5'))
            localapplicationhashes.append(file)
            if debug >= 3:
                print('\tFilename: ' + str(file) + ' : ' + 'Hash: ' + str(Hasher(outputpath + '\\' + file, 'md5')))
    except:
        error = False
        status = 'Error: Cannot generate local hashes.'
    finally:
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
    global debug

    parser = argparse.ArgumentParser(description="A program to pull all apks off via the Android Debug Bridge.",
                                     add_help=True)
    parser.add_argument('-o', '--output', help='The output path to write the apk files to.', required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('-s', '--scan', help='The level of debugging.', required=False)
    parser.add_argument('-l', '--list', help='The level of debugging.', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    if args.output:
        outputpath = args.output
        if not os.path.isdir(outputpath):
            print('')
            print('Error: Directory --> ' + str(outputpath) + ' does not exist.')
            sys.exit(1)
    if args.scan:
        scan = args.scan
    if args.debug:
        debug = args.debug
        debug = int(debug)
    Header(outputpath)
    print('| [#] Checking status of device                                            |')
    status, error = DeviceCheck()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Listing APK Files.                                                   |')
    status, error, applications = ListAPKs()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Calculating AVD APK Hashes.                                          |')
    status, error, applicationhashes = GenerateHashAVD(applications)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Pulling APK Files.                                                   |')
    status, error = PullAPKs(applications, outputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Calculating Local APK Hashes.                                        |')
    status, error, localapplicationhashes = GenerateHashLocal(outputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Comparing APK Hashes.                                                |')
    status, error = CompareHashes(applicationhashes, localapplicationhashes)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    if status:
        Completed()
        List(outputpath)


main(sys.argv[1:])