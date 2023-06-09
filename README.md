# RSA-Padding-Oracle

This tool is an implementation of the Bleichenbacher's attack on RSA PKCS1.5 padding

# Usage :

```bash
$ ./example_exploit.py  -h
usage: example_exploit.py [-h] [-v] [--debug] -H HOST -P PORT -e EXPONENT -c CIPHERTEXT -n MODULUS

options:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode. (default: False)
  --debug               Debug mode.
  -H HOST, --host HOST  Host to connect to.
  -P PORT, --port PORT  Port to connect to.
  -e EXPONENT, --exponent EXPONENT
  -c CIPHERTEXT, --ciphertext CIPHERTEXT
  -n MODULUS, --modulus MODULUS
```

# Input: 

[_check_padding_](https://github.com/Vozec/RSA-Padding-Oracle/blob/main/example_exploit.py#L28-L30) is a function that takes integer as input and returns if the decrypted integer is PKCS1.5 conforming.  
⚠️**Warning: This function as to be edited to match your challenge context.**

# References:
- https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
- https://eprint.iacr.org/2018/1173.pdf
- https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-3/

