__author__ = 'khanta'
# MY Api Key for VirusTotal - bd527801758bee752fe0aef5a52e87f5020eb1359f0b3b0e458b596373db1ce0
# http://code.activestate.com/recipes/146306/ -- multi
# https://github.com/subbyte/virustotal/blob/master/virt.py
# https://www.virustotal.com/en/documentation/public-api/
import sys
import os
import logging
import subprocess
import datetime
import argparse
import signal
import http.client
import mimetypes
import json
import time
import hashlib

import requests


debug = 0


def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = http.client.HTTPConnection(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body.encode())
    print(h.getresponse())
    errcode, errmsg, headers = h.getresponse()
    return h.file.read()


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(str(L))
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def ScanVirusTotal(listoffiles):
    status = True
    error = ''
    vt = VirusTotal()
    vt.send_files(listoffiles)


def sha256sum(filename):
    """
    Efficient sha256 checksum realization

    Take in 8192 bytes each time
    The block size of sha256 is 512 bytes
    """
    with open(filename, 'rb') as f:
        m = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


class VirusTotal(object):
    def __init__(self):
        self.apikey = 'bd527801758bee752fe0aef5a52e87f5020eb1359f0b3b0e458b596373db1ce0'
        self.URL_BASE = "https://www.virustotal.com/vtapi/v2/"
        self.HTTP_OK = 200

        # whether the API_KEY is a public API. limited to 4 per min if so.
        self.is_public_api = True
        # whether a retrieval request is sent recently
        self.has_sent_retrieve_req = False
        # if needed (public API), sleep this amount of time between requests
        self.PUBLIC_API_SLEEP_TIME = 20

        self.logger = logging.getLogger("virt-log")
        self.logger.setLevel(logging.INFO)
        self.scrlog = logging.StreamHandler()
        self.scrlog.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(self.scrlog)
        self.is_verboselog = False

    def send_files(self, filenames):
        """
        Send files to scan

        @param filenames: list of target files
        """
        url = self.URL_BASE + "file/scan"
        attr = {"apikey": self.apikey}

        for filename in filenames:
            files = {"file": open(filename, 'rb')}
            res = requests.post(url, data=attr, files=files)

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if debug >= 3:
                    print('Sent:\t\t\t\t\t' + filename)
                    print('HTTP Response Code:\t\t' + str(res.status_code))
                    print('Response_code:\t\t\t\t' + str(resmap["response_code"]))
                    print('Scan_id:\t\t\t\t' + resmap["scan_id"])
                    # if not self.is_verboselog:
                    #    self.logger.info("sent1: %s, HTTP: %d, response_code: %d, scan_id: %s",
                    #            os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_id"])
                    #else:
                    #    self.logger.info("sent2: %s, HTTP: %d, content: %s", os.path.basename(filename), res.status_code, res.text)
            else:
                print('error')
        return
        # self.logger.warning("sent3: %s, HTTP: %d", os.path.basename(filename), res.status_code)

    def retrieve_files_reports(self, filenames):
        """
        Retrieve Report for file

        @param filename: target file
        """
        for filename in filenames:
            res = self.retrieve_report(sha256sum(filename))

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verboselog:
                    self.logger.info(
                        "retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
                        os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_date"],
                        resmap["positives"], resmap["total"])
                else:
                    self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename),
                                     res.status_code, res.text)
            else:
                self.logger.warning("retrieve report: %s, HTTP: %d", os.path.basename(filename), res.status_code)

    def retrieve_from_meta(self, filename):
        """
        Retrieve Report for checksums in the metafile

        @param filename: metafile, each line is a checksum, best use sha256
        """
        with open(filename) as f:
            for line in f:
                checksum = line.strip()
                res = self.retrieve_report(checksum)

                if res.status_code == self.HTTP_OK:
                    resmap = json.loads(res.text)
                    if not self.is_verboselog:
                        self.logger.info(
                            "retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
                            checksum, res.status_code, resmap["response_code"], resmap["scan_date"],
                            resmap["positives"], resmap["total"])
                    else:
                        self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename),
                                         res.status_code, res.text)
                else:
                    self.logger.warning("retrieve report: %s, HTTP: %d", checksum, res.status_code)

    def retrieve_report(self, chksum):
        """
        Retrieve Report for the file checksum

        4 retrieval per min if only public API used

        @param chksum: sha256sum of the target file
        """
        if self.has_sent_retrieve_req and self.is_public_api:
            time.sleep(self.PUBLIC_API_SLEEP_TIME)

        url = self.URL_BASE + "file/report"
        params = {"apikey": self.apikey, "resource": chksum}
        res = requests.post(url, data=params)
        self.has_sent_retrieve_req = True
        return res


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
            if debug >= 2:
                print('\tDevice not attached.')
            error = 'Error: Device not attached.'
            status = False
    except:
        error = 'Error: Device not detected.'
        status = False
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
        # filenames = next(os.walk((outputpath)))[2]
        #filenames = (os.path.abspath(filenames))
        filenames = listdir_fullpath(outputpath)
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
        return status, error, localapplicationhashes, filenames


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
    if hashtype == 'sha256':
        sha256 = hashlib.sha256()
        with open(filename, 'rb') as f:
            for chunk in iter(lambda: f.read(128 * sha256.block_size), b''):
                sha256.update(chunk)
        return sha256.hexdigest()


def listdir_fullpath(outputpath):
    return [os.path.join(outputpath, f) for f in os.listdir(outputpath)]

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
    filenames = listdir_fullpath(outputpath)
    for file in filenames:
        print('  App: ' + file + ' -- ' + 'MD5Hash: ' + Hasher(file, 'md5'))
    if not scan:
        for file in filenames:
            print('  VirusTotal Link: ' + file + ' -- ' + 'https://www.virustotal.com/en/file/' + Hasher(file,
                                                                                                         'sha256') + '/analysis/')
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
    scan = False
    parser = argparse.ArgumentParser(description="A program to pull all apks off via the Android Debug Bridge.",
                                     add_help=True)
    parser.add_argument('-o', '--output', help='The output path to write the apk files to.', required=True)
    parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
    parser.add_argument('-s', '--scan', help='The level of debugging.', action='store_true', required=False)
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
        scan = True
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
    status, error, localapplicationhashes, filenames = GenerateHashLocal(outputpath)
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
    if scan:
        print('| [#] Uploading to VirusTotal.                                             |')
        ScanVirusTotal(filenames)
    if status:
        Completed()
        List(outputpath, scan)


main(sys.argv[1:])