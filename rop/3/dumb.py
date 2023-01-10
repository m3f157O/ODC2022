from pwn import *


if "REMOTE" not in args:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/rop/3/positiveleak')
	pid=gdb.attach(r)
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 3003)

BIN = ELF("./positiveleak")
LIBC = ELF("./libc-2.27.so")


r.interactive()



