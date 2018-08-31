from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import json
import virustotal
import os
import util
import time
import os

BASE_DIR = '/tmp/djangotest/'
FINAL_DIR = '/tmp/djangotest/final/'
def hello(request):
	resource = uploadresult['resource']
	result = virustotal.retrive(resource)
	return HttpResponse(json.dumps(result[0]),content_type="application/json")
@csrf_exempt
def upload(request):
	namestamp = str(int(time.time()))
	if request.method == 'POST':
        	obj = request.FILES.get('fa')
		filename = namestamp
		f = open(os.path.join(BASE_DIR, filename), 'wb')
		for chunk in obj.chunks():
			f.write(chunk)
	        f.close()
	nameid = util.GetFileMd5(namestamp)
	name = obj.name
	result = util.DBSelectbyId(nameid)
	count = result.count()
	resultDict = {}
	if count<1:
		util.DBInsert(nameid,name,namestamp,0,0,0.0)
		os.system('mv '+BASE_DIR+namestamp+' '+FINAL_DIR+nameid)
		taskid = util.uploadFile(nameid)
		util.TaskInsert(nameid,taskid)
		resultDict['md5'] = nameid
		resultDict['exist'] = 'new'
		print virustotal.retriveByMD5(nameid)
		virustotal.submitFile(nameid)
		
		return  HttpResponse(json.dumps(resultDict),content_type="application/json")
	else:
		os.system('rm '+BASE_DIR+namestamp)
		resultDict = {}
		resultDict['md5'] = nameid
		resultDict['exist'] = 'exist'
		status,resultjson = util.checkIsDone(nameid)
                tmpResult = {}
                tmpResult['virusTotalTrue'] = result[0].virusTotalTrue
                tmpResult['virusTotalFasle'] = result[0].virusTotalFalse
                tmpResult['cuckooScore'] = result[0].cuckooScore
		resultDict['data'] = json.dumps(tmpResult)
		return  HttpResponse(json.dumps(resultDict),content_type="application/json")
@csrf_exempt
def retriveByMd5(request):
	resultDict = {}
	resultDict['md5'] = None
	resultDict['exist'] = 'none exist'
	resultDict['data'] = None
	if request.method == 'GET':
		md5 = request.GET.get('md5')
		resultDict['md5'] = md5
		virusresult = util.DBSelectbyId(md5)
		if virusresult.count()>0:
			status,resultjson = util.checkIsDone(md5)
			resultDict['md5'] = md5
        		resultDict['exist'] = 'exist'
			tmpResult = {}
			tmpResult['virusTotalTrue'] = virusresult[0].virusTotalTrue
			tmpResult['virusTotalFasle'] = virusresult[0].virusTotalFalse
			tmpResult['cuckooScore'] = virusresult[0].cuckooScore
			resultDict['data'] = json.dumps(tmpResult)
		else:
			resultDict['exist'] = 'none exist'
	return HttpResponse(json.dumps(resultDict),content_type="application/json")
@csrf_exempt
def retriveDetailByMd5(request):
	resultDict = {}
        resultDict['md5'] = None
        resultDict['exist'] = 'none exist'
        resultDict['data'] = None
	if request.method == 'GET':
                md5 = request.GET.get('md5')
		resultDict['md5'] = md5
		virusresult = util.DBSelectbyId(md5)
		if virusresult.count()>0:
                	status,resultjson = util.checkIsDone(md5)
                	detailVirusjson = virustotal.retriveDetailByMD5(md5)
                	resultDict['exist'] = 'exist'
	                #resultDict['data'] = resultjson
        	        tmpResult = {}
                	tmpResult['virusTotalTrue'] = virusresult[0].virusTotalTrue
	                tmpResult['virusTotalFasle'] = virusresult[0].virusTotalFalse
        	        tmpResult['cuckooScore'] = virusresult[0].cuckooScore
			tmpResult['detail'] = detailVirusjson
	                resultDict['data'] = json.dumps(tmpResult)
        return HttpResponse(json.dumps(resultDict),content_type="application/json")

