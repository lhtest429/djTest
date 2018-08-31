import requests

def testUpload(): 
	url = 'http://127.0.0.1:8081/api/upload'
	files = {'fa': open('/home/lenard_li/explorer.exe', 'rb')}           
	data = {'filename':'filename'}
	response = requests.post(url, files=files, data=data)
	json = response
	print (json.text)
def testRetrive():
	url = 'http://127.0.0.1:8081/api/retrive'
	data = {'md5':'07e5a1a4d98cba85f460294ba19d27da'}
	response = requests.get(url,params = data)
	json = response
	print (json.text)
def testRetriveDetail():
        url = 'http://127.0.0.1:8081/api/detail'
        data = {'md5':'eaf01745453ea120b0e2215599c40a91'}
        response = requests.get(url,params = data)
        json = response
        print (json.text)
testRetrive()
#testUpload()
#testRetriveDetail()
