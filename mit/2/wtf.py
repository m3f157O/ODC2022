from pwn import *
import sys
 
context.clear(arch='amd64',os='linux')

if(len(sys.argv)>1):
	run_local = False
else:
	run_local = True

print(run_local)
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/leakers')
	pid=gdb.attach(r)
	input("wait")
else:
	r=remote("bin.training.jinblack.it",2011)


r.interactive()

