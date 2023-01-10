from pwn import *

def xor_strings(a, b):
    result = int(a, 16) ^ int(b, 16) # convert to integers and xor them together
    return '{:x}'.format(result)     # convert back to hexadecimal


key = [b'\x19',
b'\x83',
b'\x89',
b'\xd2',
b'\x6e',
b'\x1f',
b'\x84',
b'\x1c',
b'\x94',
b'\x11',
b'\x31',
b'\x82',
b'\xde',
b'\x04',
b'\xe9',
b'\x9b',
b'\xf0',
b'\xc9',
b'\x18',
b'\xbb',
b'\x82',
b'\x51',
b'\xaa',
b'\xba',
b'\x13',
b'\x9e',
b'\x44',
b'\xec',
b'\x49',
b'\xe5',
b'\xad',
b'\x49',
b'\x01',
b'\x86',
b'\xab',
b'\x39',
b'\x6a']

flag = [b'\x7f',
b'\xef',
b'\xe8',
b'\xb5',
b'\x15',
b'\x73',
b'\xb4',
b'\x6a',
b'\xa7',
b'\x7d',
b'\x48',
b'\xdd',
b'\xea',
b'\x6a',
b'\x9d',
b'\xaa',
b'\x82',
b'\xfa',
b'\x6e',
b'\xe4',
b'\xf6',
b'\x23',
b'\x9b',
b'\xd9',
b'\x78',
b'\xab',
b'\x1b',
b'\x9b',
b'\x16',
b'\x96',
b'\x9c',
b'\x2e',
b'\x6f',
b'\xb2',
b'\xc7',
b'\x0c',
b'\x17']

print(len(key))
print(len(flag))

dec_flag = ''

for i in range(len(key)):
    dec_flag += chr(int.from_bytes(key[i], byteorder='little') ^ int.from_bytes(flag[i], byteorder='little'))

print(dec_flag)
