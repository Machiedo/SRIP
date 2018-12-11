from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.backends import default_backend
from os import path
from os import urandom
import base64
from itertools import count

STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama

CHALLENGE = "Chuck Norris je vodu iz pipe popio na eks!"


# Generate hash
def hash_me(msg, hash_function):
    digest = hashes.Hash(hash_function, backend=default_backend())
    if not isinstance(msg, bytes):
        msg = msg.encode()
    digest.update(msg)
    return digest.finalize()


def encrypt_CTR(key, iv, plaintext, cipher=algorithms.AES):
    if not isinstance(key, bytes):
        key = key.encode()
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode()

    encryptor = Cipher(cipher(key), modes.CTR(iv), backend=default_backend()).encryptor()
    ciphertext = encryptor.update(plaintext)
    ciphertext += encryptor.finalize()

    return ciphertext


def decrypt_CTR(key, iv, ciphertext, cipher=algorithms.AES):
    if not isinstance(key, bytes):
        key = key.encode()

    decryptor = Cipher(cipher(key), modes.CTR(iv), backend=default_backend()).decryptor()
    plaintext = decryptor.update(ciphertext)
    plaintext += decryptor.finalize()

    return plaintext


if __name__ =='__main__':

    # Generate passcode
    passcode = str(int.from_bytes(urandom(2), byteorder='big') & 0x0FFF)
    passcode = passcode.encode()

    # Generate key
    KDF = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=50000,
        backend=default_backend()
    )
    key = KDF.derive(passcode)

    iv = urandom(16)
    ciphertext = encrypt_CTR(key, iv, CHALLENGE)

    challenge_file_name = hash_me(str.encode(STUDENTNAME + SALT), hashes.SHA256()).hex() + '.enc'
    with open(challenge_file_name, 'wb') as f:
        content_to_write = base64.b64encode(iv + ciphertext)
        f.write(content_to_write)

content="UxbJxNpYgU94q2bBv0RH+4hUWQEm8Cxq7xNbJm9B+MYVU2e4MFBVmncGxZ54y5RtCrzyx29YJO8TfTmzVwbYotgIrWvdgm1tvTXqSBlhi8uVR82KnII9fisawtU1imWS7h7pUll1/sNbYPCOHlfl03h2xXh+sw8+yeMdndlBnHZTSUfzfa92fk8RQt579TsLaS/jAIQGBpB5uDJOVVsrsZ53Mm9dOLDwWYs2kMpBi1jorgM4sG0="

ciphertext_decoded=base64.b64decode(content)
iv=ciphertext_decoded[:16]
ciphertext=ciphertext_decoded[16:]

for ctr in count():
    pswd=str(ctr)
    pswd=pswd.encode()
    KDF=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'salt',
        iterations=50000,
        backend=default_backend()
    )
    k=KDF.derive(pswd)
    plaintext=decrypt_CTR(k,iv,ciphertext)
    if b'Chuck' not in plaintext:
        print(ctr)
    else:
        print("Key is ")
        print(ctr)
        print(plaintext)
        break
