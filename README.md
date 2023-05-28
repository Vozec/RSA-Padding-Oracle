# RSA-Padding-Oracle
This tool is an implementation of the Bleichenbacher's attack on RSA PKCS1.5 padding
# Usage :

```python
from RSA_Padding_Attack import *

from Crypto.Util.number import long_to_bytes
from pwn import *
context.log_level = 'critical'

class Oracle:
	def __init__(self,url,port):
		self.url = url
		self.port = port
		self.p = remote(self.url,self.port)

	def check_padding(self,ct: int) -> bool:
		self.p.send(ltb(ct))
		return b'padding is ok' in self.p.recvline()

oracle = Oracle(
	url = '...',
	port = ...
)

exploit = Bleichenbacher_Padding_Attack(
	e = ...,
	c = ...,
	n = ...,
	oracle = oracle,
	verbose = True
)
m = exploit.attack()
print(long_to_bytes(m))
```

# Input: 

*check_padding* is a function that takes int as input and returns if the decrypted int is PKCS conforming

# Refs:
- https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
- https://eprint.iacr.org/2018/1173.pdf
- https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-3/

