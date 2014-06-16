__author__ = 'khanta'
# http://stackoverflow.com/questions/2789462/find-package-name-for-android-apps-to-use-intent-to-launch-market-app-from-web - AAPT
# http://developer.android.com/tools/devices/managing-avds-cmdline.html
# echo no | c:\adt\sdk\tools\android.bat create avd -n test -t android-17 --abi default/x86

# REM C:\android\sdk\tools\mksdcard -l e 512M c:\temp\mysdcard.img
# REM C:\android\sdk\tools\emulator.exe -avd test -partition-size 512 -noaudio -no-snapshot -sdcard c:\temp\mysdcard.img#-tcpdump emu.pcap
# adb shell mount -o rw,remount -t yaffs2 /dev/block/mtdblock0 /system
# adb shell mkdir -p /system/vendor/bin
# adb push busybox-i686 /system/vendor/bin
# adb shell chmod 755 /system/vendor/bin/busybox-i686
# adb install com.golfnow.android.teetimes-1.apk
# adb shell mount -o remount rw /sdcard
# adb shell tcpdump -s 0 -w /mnt/sdcard/$app.pcap
# adb shell touch /mnt/sdcard/starttime
# adb shell am start -a android.intent.action.MAIN -n com.golfnow.android.teetimes/.ui.StartupActivity
# adb shell screencap -p /mnt/sdcard/1.png
# sleep 5s
# adb shell /system/vendor/bin/busybox-i686 find / \( -type f -a -newer /mnt/sdcard/starttime \) -o -type d -a \( -name dev -o -name proc -o -name sys \) -prune | grep -v -e "^/dev$" -e "^/proc$" -e "^/sys$"
# http://stackoverflow.com/questions/305378/get-list-of-tables-db-schema-dump-etc-in-sqlite-databases
# identify files, if sqllite, check majic and print out schema, tables.
# con = sqlite3.connect('database.db')
# cursor = con.cursor()
# cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
# print(cursor.fetchall())
# https://github.com/codasus/django-sqlcipher

import argparse
import sys
import datetime
import hashlib
import os
import subprocess

import adbpull


debug = 0




def ListLocalAPKFiles(inputpath):
    status = True
    error = ''
    listoffiles = {}
    x = 1

    if debug >= 1:
        print('Entering ListLocalAPKFiles')
    if debug >= 2:
        print('\tInput path passed in: ' + str(inputpath))
    for filename in os.listdir(inputpath):
        if filename.endswith('apk'):
            if debug >= 2:
                print('\tIterator:Filename - ' + str(x) + ':' + filename)
            listoffiles[x] = filename
            x += 1
    # for root, dirs, files in os.walk(inputpath):
    # for file in files:
    #         if file.endswith('.apk'):
    #             if debug >= 2:
    #                 print('\tIterator:Filename - ' + str(x) + ':' + file)
    #             listoffiles[x] = file
    #             x += 1
    if debug >= 3:
        print('\tList of Files: ' + str(listoffiles))

    return status, error, listoffiles

def ListDeviceAPKs():
    status = True
    error = ''
    # applications = []
    applications = {}
    x = 1

    try:
        if debug >= 1:
            print('Entering ListAPKs')
        if debug >= 2:
            print('\tLaunching command "adb shell pm list packages"')
        p = subprocess.Popen('adb shell pm list packages', shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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


def GetApplicationName(inputpath, application):
    status = True
    error = ''
    package = ''

    try:
        if debug >= 1:
            print('GetApplicationName ListAPKs')
        if debug >= 2:
            print('\tLaunching command "aapt dump badging"')
        p = subprocess.Popen(
            'c:\\android\\sdk\\build-tools\\19.1.0\\aapt dump badging ' + inputpath + '\\' + application,
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            temp = line.decode("ASCII").rstrip()
            if 'package: name=' in temp:
                data = (temp.split('\''))
                break
            else:
                continue

        package = data[1]
        if debug >= 2:
            print('\tPackage name: ' + str(package))
    except:
        error = 'Error: Cannot get package name.'
        status = False
    finally:
        return status, error, package


def UninstallAPK(application):
    status = True
    error = ''

    try:
        if debug >= 1:
            print('Entering UninstallAPK')
        if debug >= 2:
            print('\tApplication name passed in: ' + str(application))
            print('\tLaunching command "adb shell pm uninstall ' + str(application) + '"')
        p = subprocess.check_output('adb shell pm uninstall ' + application)
        temp = p.decode("ASCII").rstrip()
        if debug >= 2:
            print('\tReturn text: ' + str(temp))
        if temp.lower() != 'success':
            error = 'Error: Cannot uninstall APK.'
            status = False
            return status, error
    except:
        error = 'Error: Cannot uninstall APK.'
        status = False
    finally:
        return status, error


def InstallAPK(inputpath, application):
    status = True
    error = ''

    try:
        if debug >= 1:
            print('Entering InstallAPK')
        if debug >= 2:
            print('\tInput path passed in: ' + str(inputpath))
            print('\tApplication passed in: ' + str(application))
            print('\tLaunching command "adb install ' + inputpath + str(application) + '"')
        p = subprocess.check_output('adb install ' + inputpath + '\\' + str(application))
        temp = p.decode("ASCII").rstrip()
        if debug >= 2:
            print('\tReturn text: ' + str(temp))
        if 'success' not in temp.lower():
            error = 'Error: Cannot install APK.'
            status = False
            return status, error

    except:
        error = 'Error: Cannot install APK.'
        status = False
    finally:
        return status, error


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


def ExistsInDictionary(name, devicedict, type):
    status = True
    error = ''
    if type.upper() == 'KEY':
        if name in devicedict.keys():
            status = True
        else:
            status = False
            error = 'Error: Number not within range.'
    if type.upper() == 'VALUE':
        if name in devicedict.values():
            status = True
        else:
            status = False
            error = 'Not sure yet.'
    return status, error

def GetModifiedFiles():
    status = True
    error = ''

    status, error = adbpull.DeviceCheck()
    if not status:
        status = False
        return status, error

    p = subprocess.check_output(
        'adb shell find / \( -type f -a -newer /mnt/sdcard/starttime \) -o -type d -a \( -name dev -o -name proc -o -name sys \) -prune | grep -v -e "^/dev$" -e "^/proc$" -e "^/sys$"')
    # temp = p.decode("ASCII").rstrip()
    #print(p.decode("ASCII").rstrip())
    #print(temp)
    return status, error, p


def CreateTimeStamp():
    status = True
    error = ''

    status, error = adbpull.DeviceCheck()
    if not status:
        status = False
        return status, error
    else:
        if debug >= 1:
            print('Entering CreateTimeStamp')
            if debug >= 2:
                print('\tLaunching command "adb shell touch /mnt/sdcard/starttime"')
            subprocess.call('adb shell touch /mnt/sdcard/starttime')
    return status, error


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
    print('| [#] Checking status of device.                                           |')
    status, error = adbpull.DeviceCheck()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Listing local APK Files.                                             |')
    status, error, localapplications = ListLocalAPKFiles(inputpath)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Listing Device APK Files.                                            |')
    print('+--------------------------------------------------------------------------+')
    status, error, deviceapplications = ListDeviceAPKs()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| Local APKs:                                                              |')
    print('+--------------------------------------------------------------------------+')
    for num, apps in localapplications.items():
        # print('| \t ' + str(num) + ' - ' + str(apps))
        #print((str(num) + ' - ' + str(apps)).center(76))
        print(('| \t ' + str(num) + ' - ' + str(apps)).ljust(74, ' ') + '|')
    print('+--------------------------------------------------------------------------+')
    if debug >= 2:
        print('\tLocal Applications: ' + str(localapplications))
    userselection = input(" Select an application by number: ")
    if debug >= 2:
        print('\tUser Selection: ' + userselection)
    status, error, number = ConverToInt(userselection)
    if not status:
        print('| [-] Failed.                                                              |')
        Failed(error)
    status, error = ExistsInDictionary(number, localapplications, 'KEY')
    if status:
        application = localapplications[number]
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('+--------------------------------------------------------------------------+')
    print('|                                                                          |')
    print('+--------------------------------------------------------------------------+')
    print('| [#] Enumerating package name.                                            |')
    status, error, package = GetApplicationName(inputpath, application)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    status, error = ExistsInDictionary('package:' + package, deviceapplications, 'VALUE')
    if status:
        print('| [#] Application exists on AVD. Uninstalling.                             |')
        status, error = UninstallAPK(package)
        if status:
            print('| [+] Success.                                                             |')
        else:
            print('| [-] Failed.                                                              |')
            Failed(error)
    print('| [#] Installing application on AVD.                                        |')
    status, error = InstallAPK(inputpath, application)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    print('| [#] Creating initial timestamp file.                                      |')
    status, error = CreateTimeStamp()
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        Failed(error)
    # LaunchMainItent()
    go = input(" Go?: ")
    print('| [#] Gathering modified files.                                             |')
    status, error, modifiedfiles = GetModifiedFiles()
    print(modifiedfiles)
    if status:
        print('| [+] Success.                                                             |')
    else:
        print('| [-] Failed.                                                              |')
        #TODO Set Timestamp
        #TODO Get Files Modded
        #TODO Pull files Modded
        #TODO Do Device Check every time
        # TODO Choose a list of emulator devices - start it if stopcd\ped
        #TODO Start NIC traffic capture - do it - stop device stop nic traffic capture
        # TODO Make sure HAXD Driver is installed
        #TODO Create AVD --> android.bat create avd -n test -t android-17 --abi default/x86
        #TODO Start AVD --> emulator.exe -avd test -partition-size 512 -no-snapshot -tcpdump <pcap>
        #TODO adb shell
        #   adb shell mount -o rw,remount -t yaffs2 /dev/block/mtdblock0 /system
        #   adb shell mkdir -p /system/vendor/bin
        #   spawn off adb push busybox-i686 /system/vendor/bin
        #   adb shell chmod 755 /system/vendor/bin/busybox-i686
        # adb shell /system/vendor/bin/busybox-i686 find xyz

        #TODO Delete AVD --> android.bat delete avd -n test
        #TODO Start AVD -->


main(sys.argv[1:])