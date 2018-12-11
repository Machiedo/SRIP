from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import (
    hashes,
    padding
)
from cryptography.hazmat.backends import default_backend
import os
import base64


KEY_BLOCK_SIZE = 32
CIPHER_BLOCK_LENGTH = 128
IV_BLOCK_SIZE = 16
CIPHER = algorithms.AES

STUDENTNAME = "MachiedoDani" # ne koriste se HR slova (čćžšđ)
SALT = "FESBSRPFESBSRP" # pitajte profesora na vježbama

QUOTE = "The lock on the old door could only take short keys"


def encrypt(key, iv, plaintext):
    ''' Function encrypt '''

    padder = padding.PKCS7(CIPHER_BLOCK_LENGTH).padder()
    padded_plaintext = padder.update(plaintext)
    padded_plaintext += padder.finalize()

    cipher = Cipher(CIPHER(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext)
    ciphertext += encryptor.finalize()

    return ciphertext

def decrypt(key, iv, ciphertext):
    cipher=Cipher(CIPHER(key),modes.CTR(iv),backend=default_backend())
    decryptor=cipher.decryptor()
    plaintext=decryptor.update(ciphertext)
    plaintext+=decryptor.finalize()

    unpadder=padding.PKCS7(CIPHER_BLOCK_LENGTH).unpadder()
    unpadded_plaintext=unpadder.update(plaintext)
    unpadded_plaintext+=unpadder.finalize()

    return unpadded_plaintext

if __name__ =='__main__':



    written_content="airSsKotRft5Klk5TRH31oMv2GthZfBp1/ON7F9HcbvKCjGFvy7wV/dOtyCkSOZJ1hPANgNSh/ra7Jktw25Ty95DunPAg9WUmJ4+hQQ1QzWCpSmKv2IYJ1lbC05l+uVPw97sxNV1GWG5829+c3AwgqbKwX7jeUhyePS5ovTw/Ldv135v46QyheE/AaBrxZh2"

    challenge=base64.b64decode(written_content)

    iv=challenge[:16]
    key=challenge[-32:]
    ciphertext=challenge[16:-32]
    
    plaintext=decrypt(key,iv,ciphertext)
    print(plaintext)
    


    '''
    key = os.urandom(KEY_BLOCK_SIZE)
    iv = os.urandom(IV_BLOCK_SIZE)
    enc = encrypt(key, iv, str.encode(QUOTE))
    '''
    '''
    f_out = open(filename + ".enc", 'wb')
    content_to_write = base64.b64encode(iv + enc + key)
    f_out.write(content_to_write)
    f_out.close()
    '''

decrypt(key,iv,ciphertext)
