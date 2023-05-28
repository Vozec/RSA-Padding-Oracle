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