__author__ = 'khanta'

import argparse
import sys
import datetime
import hashlib
import os
import subprocess

debug = 0


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
            if debug >= 2:
                print('\tDevice not attached.')
            error = 'Error: Device not attached.'
            status = False
    except:
        error = 'Error: Device not detected.'
        status = False
    finally:
        return status, error


def ListLocalAPKFiles(inputpath):
    status = True
    error = ''
    listoffiles = {}
    x = 0

    if debug >= 1:
        print('Entering ListLocalAPKFiles')
    if debug >= 2:
        print('\tOutput path passed in: ' + str(inputpath))

    for root, dirs, files in os.walk(inputpath):
        for file in files:
            if file.endswith('.apk'):
                if debug >= 2:
                    print('\tIterator:Filename - ' + str(x) + ':' + file)
                listoffiles[x] = file
                x += 1
    if debug >= 3:
        print('\tList of Files: ' + str(listoffiles))

    return status, error, listoffiles


def ListDeviceAPKs():
    status = True
    error = ''
    # applications = []
    applications = {}
    x = 0

    try:
        if debug >= 1:
            print('Entering ListAPKs')
        if debug >= 2:
            print('\tLaunching command "adb shell ls /data/app"')
        p = subprocess.Popen('adb shell ls /data/app', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            if debug >= 3:
                print('\tApplications on AVD: ' + str(line.decode("ASCII").rstrip()))
            #applications.append(line.decode("ASCII").rstrip())
            applications[x] = line.decode("ASCII").rstrip()
            x += 1
        if debug >= 3:
            print('\tList of Applications on the AVD: ' + str(applications))
            # retval = p.wait()
    except:
        error = 'Error: Cannot list APK files.'
        status = False
    finally:
        return status, error, applications


def ConverToInt(s):
    status = True
    error = ''
    ret = 0

    try:
        ret = int(s)
    except ValueError:
        status = False
        error = 'Error: Value entered is not an integer.'
    finally:
        return status, error, ret


def ExistsInDictionary(name, devicedict):
    if name in devicedict.values():
        return True


def Hasher(filename, hashtype):
    with open(filename, 'rb') as f:
        file = f.read()

        if hashtype.upper() == 'MD5':
            return hashlib.md5(file).hexdigest()
        if hashtype.upper() == 'SHA1':
            return hashlib.sha1(file).hexdigest()
        if hashtype.upper() == 'SHA256':
            return hashlib.sha256(file).hexdigest()
        else:
            return 'No Hashtype specified.'

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


def List(outputpath, scan):
    print('|Output                                                                    |')
    print('+--------------------------------------------------------------------------+')
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
    global debug
    parser = argparse.ArgumentParser(description="A program to determine files touched by initial launch of APK.",
                                     add_help=True)
    parser.add_argument('-o', '--output', help='The output path to write the files to.', required=True)
    parser.add_argument('-i', '--input', help='The input path to read the APK files from.', required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    if args.output:
        outputpath = args.output
        if not os.path.isdir(outputpath):
            print('')
            print('Error: Directory --> ' + str(outputpath) + ' does not exist.')
            sys.exit(1)
    if args.input:
        inputpath = args.input
    if args.debug:
        debug = args.debug
        debug = int(debug)
    Header(outputpath)
    print('| [#] Checking status of device.                                               |')
    status, error = DeviceCheck()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Listing local APK Files.                                                 |')
    status, error, localapplications = ListLocalAPKFiles(inputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Listing Device APK Files.                                                |')
    status, error, deviceapplications = ListDeviceAPKs()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| Local APKs:                                                                  |')
    for num, apps in localapplications.items():
        print('| \t ' + str(num) + ' - ' + str(apps))
    if debug >= 2:
        print('\tLocal Applications: ' + str(localapplications))
    userselection = input("Select an application by number: ")
    if debug >= 2:
        print('\tUser Selection: ' + userselection)
    status, error, number = ConverToInt(userselection)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)

    if debug >= 2:
        print('\tSelected application: ' + str(localapplications[number]))
    application = localapplications[number]
    if ExistsInDictionary(application, localapplications):
        x = 1


main(sys.argv[1:])