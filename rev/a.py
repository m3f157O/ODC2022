import claripy
from pwn import *
import angr

r=process("./crackme",argv='flag{')
r.interactive()


