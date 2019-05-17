import time
import hashlib
import urllib
import urllib2
import json

import data

def getVerifyCodeString():
	timestamptmp=(long)(time.time()*1000)
	timestamp=str(timestamptmp)
	temp=(data.clientip)+(data.nasip)+(data.mac)+(timestamp)+(data.secret)
	md5String=hashlib.md5(temp.encode('utf-8')).hexdigest().upper()
	test_data={'iswifi':'4060' , 'clientip':data.clientip , 'nasip':data.nasip , 'mac':data.mac , 'timestamp':timestamp , 'authenticator':md5String , 'username':data.username}
	headers={'Content-Type': 'application/json'}
	request=urllib2.Request(url='http://61.140.12.23:10001/client/challenge', headers=headers, data=json.dumps(test_data))
	response=urllib2.urlopen(request)
	resoutput=response.read()
	task_json=json.loads(resoutput)
	if task_json['challenge']:
		return task_json['challenge']
	
def doLogin(vertifyCode):
	timestamptmp=(long)(time.time()*1000)
	timestamp=str(timestamptmp)
	temp=(data.clientip)+(data.nasip)+(data.mac)+(timestamp)+(vertifyCode)+(data.secret)
	md5String=hashlib.md5(temp.encode('utf-8')).hexdigest().upper()
	test_data={'password':data.password , 'iswifi':'4060' , 'clientip':data.clientip , 'nasip':data.nasip , 'verificationcode':'' , 'authenticator':md5String , 'mac':data.mac , 'username':data.username , 'timestamp':timestamp}
	headers={'Content-Type': 'application/json'}
	request=urllib2.Request(url='http://61.140.12.23:10001/client/login', headers=headers, data=json.dumps(test_data))
	response=urllib2.urlopen(request)
	resoutput=response.read()
	print(resoutput)

def main():
	vertifyCode=getVerifyCodeString()
	doLogin(vertifyCode)

if __name__=='__main__':
	main()