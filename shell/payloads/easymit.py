from pwn import *
from time import time


context.clear(arch='amd64',os='linux')
run_local = True
if run_local:
	r= process('./ptr_protection')
else:
	r=remote("bin2.ctf.offdef.it",4001)





gdb.attach(r)
input('wait')
r.interactive()

