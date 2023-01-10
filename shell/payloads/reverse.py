import sys
from pwn import *

input = sys.argv[1]

if(input[:2]=="0x"):
	input= input[2:]

split_strings = []

n  = 2

for index in range(0, len(input), n):

    split_strings.append(input[index : index + n])

split_strings.reverse()
print(split_strings)

input=''.join(split_strings)


print("Reversing endianess: "+ input)


bytes_object = bytes.fromhex(input) 
ascii_string = bytes_object.decode("ASCII") 


print("Converted to ASCII: "+ ascii_string)

pattern= ascii_string
print(type(ascii_string))
#offset= cyclic_gen(string.ascii_lowercase).get(sys.argv[2]).find(pattern)

if(offset == -1):
	print("Try another time")
else:
	print("Stack smash starting from: "+offset)
