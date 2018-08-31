import hashlib
import os
import datetime
import requests
from django.db import connection
from django.db import models
from Virus.models import VirusPath,Task
import json
import virustotal

BASE_DIR = '/tmp/djangotest/'
def GetFileMd5(filename):
	if not os.path.isfile(BASE_DIR+filename):
		return
	myhash = hashlib.md5()
	f = file(BASE_DIR+filename,'rb')
	while True:
		b = f.read(8096)
		if not b:
			break
		myhash.update(b)
	f.close()
	return myhash.hexdigest()
def DBInsert(nameid,name,namestamp,virusTotalTrue,virusTotalFalse,cuckooScore):
	t = VirusPath(nameid = nameid,name = name,namestamp = namestamp, virusTotalTrue = virusTotalTrue, virusTotalFalse = virusTotalFalse,cuckooScore = cuckooScore)
	t.save()
def DBSelectbyId(nameid):
	response = ''
	response = VirusPath.objects.filter(nameid=nameid)
	return response
def DBUpdatebyId(nameid,virusTotalTrue,virusTotalFalse,cuckooScore):
#	print (1)
	t = VirusPath.objects.get(nameid = nameid)
	t.virusTotalTrue = virusTotalTrue
	t.virusTotalFalse = virusTotalFalse
	t.cuckooScore = cuckooScore
	t.save()
def DBupdateCuckoobyId(nameid,cuckooScore):
	t = VirusPath.objects.get(nameid = nameid)
	t.cuckooScore = cuckooScore
	t.save()
def TaskInsert(nameid,taskid):
	t = Task(nameid,taskid)
	t.save()
def QueryTaskByMd5(md5):
	response = ''
	response = Task.objects.filter(nameid=md5)
	return response
def QueryMd5ByTask(taskid):
        response = ''
        response = Task.objects.filter(taskid = taskid)
        return response
def uploadFile(md5):
	REST_URL = "http://localhost:1337/tasks/create/file"
	SAMPLE_FILE = "/tmp/djangotest/final/"+md5
	with open(SAMPLE_FILE, "rb") as sample:
	    files = {"file": (md5, sample)}
	    r = requests.post(REST_URL, files=files)
	task_id = r.json()["task_id"]
	return task_id
def viewCuckooTask(taskid):
        url = "http://localhost:1337/tasks/view/"+str(taskid)
	print url
        response = requests.get(url)
        json = response.json()
        return json
def getTaskidByMd5(md5):
        taskid = QueryTaskByMd5(md5)
        return taskid
def viewCuckooResult(md5):
        taskinfo = getTaskidByMd5(md5)
	taskid = taskinfo[0].taskid
        url = "http://localhost:1337/tasks/report/"+taskid
	taskinfo = viewCuckooTask(taskid)
	status = taskinfo['task']['status']
	if status == 'reported':	
	        response = requests.get(url)
		cuckooScore = float(response.json()['info']['score'])
		#DBUpdatebyId('eaf01745453ea120b0e2215599c40a91',51,18,1)
		DBupdateCuckoobyId(md5,cuckooScore)
	        json = response.json()
        	return cuckooScore
	else:
		return None
def checkIsDone(nameid):
	response = DBSelectbyId(nameid)
	if response.count()>0:
		cuckooScore = response[0].cuckooScore
		virusTotalTrue	= response[0].virusTotalTrue
		virusTotalFalse = response[0].virusTotalFalse
		if cuckooScore == 0.0:
			cuckooScore = viewCuckooResult(nameid)
			tmpResult = {}
			tmpResult['virusTotalTrue'] = response[0].virusTotalTrue
			tmpResult['virusTotalFasle'] = response[0].virusTotalFalse
			if cuckooScore != None:
				tmpResult['cuckooScore'] = cuckooScore
			else:
				tmpResult['cuckooScore'] = 0
			return -1,json.dumps(tmpResult)
		elif virusTotalFalse == 0 and virusTotalTrue == 0:
			result = virustotal.retriveByMD5(md5)
			return 0,result
		else:
			tmpResult = {}
			tmpResult['virusTotalTrue'] = response[0].virusTotalTrue
			tmpResult['virusTotalFasle'] = response[0].virusTotalFalse
			tmpResult['cuckooScore'] = response[0].cuckooScore
			return 1,json.dumps(tmpResult)
	else:
		finalresult = virustotal.retriveByMD5(nameid)
		return -2,finalresult
