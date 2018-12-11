from cryptography.fernet import Fernet
'''
Importing the class "Fernet" from the package "cryptography",
the subpackage "fernet"; recall, (sub)packages are just ordinary
folders. You can easily verify this by looking here:
https://github.com/pyca/cryptography/tree/master/src

And yes, Python has classes and supports object-oriented
programming.
'''
key=Fernet.generate_key()
f=Fernet(key)
ciphertext=f.encrypt(b"A really secret message")

print(f"\nCiphertext: {ciphertext}")