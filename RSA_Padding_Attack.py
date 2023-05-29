#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RSA_Padding_Attack.py
# Author             : Vozec
# Date created       : 29 May 2023


class Bleichenbacher_Padding_Attack:
	def __init__(self, n, e, c, oracle, verbose=True):
		self.e = e
		self.c = c
		self.n = n
		self.oracle = oracle
		self.verbose = verbose
		self.i = 1
		self.M = set()
		self.m = None

	def check(self,c,s):
		return self.oracle.check_padding(
			c * pow(s, self.e, self.n) % self.n
		)

	def indice(self,k):
		c = "₀₁₂₃₄₅₆₇₈₉"
		return ''.join([c[int(x)] for x in str(k)])

	def log(self,msg):
		if self.verbose:
			print(msg)

	def attack(self):
		self.step_1()
		while not self.m:
			self.step_2()
			self.step_3()
			self.step_4()
			self.i += 1
		return self.m

	def step_1(self):
		self.log('[*] Starting step N°1: "Blinding"')
		k = self.n.bit_length() // 8
		B = pow(2, 8 * (k - 2))
		self.B2 = 2 * B
		self.B3 = 3 * B
		assert self.check(self.c,1)
		self.M  = {
			(self.B2,self.B3 - 1)
		}
		self.log('[+] (Step 1) | M₀ = [%s,%s]\n' % (next(iter(self.M))))

	def step_2(self):
		self.log('[*] Starting step N°2: "Searching for PKCS conforming messages"')
		if self.i == 1:
			self.s = (self.n // self.B3) + 1
			while not self.check(self.c,self.s):
				print('\tS₁ = %s' % self.s, end='\r')
				self.s += 1

		elif self.i > 1 and len(self.M) >= 2:
			self.s += 1
			while not self.check(self.c,self.s):
				print('\tS%s = %s' % (self.indice(self.i), self.s), end='\r')
				self.s += 1

		elif len(self.M) == 1:
			a, b = next(iter(self.M))
			r =  (2 * (b * self.s - self.B2)) // self.n + 1
			found = False 
			while not found:
				x = (self.B2 + r*self.n) // b + 1
				y = (self.B3 - 1 + r*self.n) // a
				for s in range(x,y+1):
					if self.check(self.c,s):
						found = True
						print('\tS%s = %s' % (self.indice(self.i), self.s), end='\r')
						self.s = s
						break
				r += 1
		if self.verbose:
			print('\x1b[A\x1b[2K', end='')
		self.log('[+] (Step 2) | S%s = %s\n' % (self.indice(self.i), self.s))

	def step_3(self):
		self.log('[*] Starting step N°3: "Reducing the set of solutions"')
		M = set()
		for a,b in self.M:
			r_min = (a * self.s - self.B3 + 1) // self.n + 1
			r_max = (b * self.s - self.B2) // self.n
			for r in range(r_min,r_max+1):
				bound_l = max(a, (self.B2 + r*self.n) // self.s + 1)
				bound_r = min(b, (self.B3 - 1 + r*self.n) // self.s)
				if bound_l <= bound_r:
					M |= {(bound_l,bound_r)}
		self.M = M

		self.log('[+] (Step 3) | M%s = %s\n' % (self.indice(self.i), self.M))

	def step_4(self):
		if len(self.M) == 1:
			self.log('[*] Starting step N°4: Checking for a solution')
			a, b = next(iter(self.M))
			if a == b:
				self.m = a
				self.log('[+] Attack succeed !')
				self.log('[*] m = %s' % self.m)
