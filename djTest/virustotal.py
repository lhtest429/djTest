#!/usr/bin/env python

from __future__ import print_function
import json
import hashlib
import requests
import util
from virus_total_apis import PublicApi as VirusTotalPublicApi
BASE_DIR = '/tmp/djangotest/final/'
apikey = ''

def submitFile(filename):
    params = {
        'apikey': apikey }
    files = {
        'file': (filename, open(BASE_DIR + filename, 'rb')) }
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files = files, params = params)
    json_response = response.json()
    return json_response


def retriveByMD5(md5):
    params = {
        'apikey': apikey,
        'resource': md5 }
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'gzip,  My Python requests library example client or username' }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params = params, headers = headers)
    json_response = response.json()
    resultList = json_response['scans']
    strresult = str(resultList)
    num_true = strresult.count('True', 0, len(strresult))
    num_false = strresult.count('False', 0, len(strresult))
    finalresult = { }
    finalresult['virusdata'] = json_response
    finalresult['num_true'] = num_true
    finalresult['num_false'] = num_false
    if util.DBSelectbyId(md5).count()>0:
	    util.DBUpdatebyId(md5, num_true, num_false, 0)
    return finalresult
def retriveDetailByMD5(md5):
    params = {
        'apikey': apikey,
        'resource': md5 }
    headers = {
        'Accept-Encoding': 'gzip, deflate',
        'User-Agent': 'gzip,  My Python requests library example client or username' }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params = params, headers = headers)
    json_response = response.json()
    resultList = json_response['scans']
    strresult = str(resultList)
    num_true = strresult.count('True', 0, len(strresult))
    num_false = strresult.count('False', 0, len(strresult))
    finalresult = { }
    finalresult['virusdata'] = json_response
    finalresult['num_true'] = num_true
    finalresult['num_false'] = num_false
    return finalresult
