# file hash_lab3.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from os import path
from os import urandom
import base64


STUDENTNAME = "PerkovicToni" # ne koriste se HR slova (čćžšđ)
SALT = "!ASK_PROFESSOR!" # pitajte profesora na vježbama


# Generate hash
def hash_me(msg, hash_function):
    digest = hashes.Hash(hash_function, backend=default_backend())
    if not isinstance(msg, bytes):
        msg = msg.encode()
    digest.update(msg)
    return digest.finalize()


if __name__ =='__main__':


    hash_challenge="X1chjXpd1KQ7/ghUStCweM/Ad54q9AFomwLpW2Xd7qM="
    hash_challenge=base64.b64decode(hash_challenge)

    randnum=0

    while True:

        candidate_challenge=str(randnum)
        candidate_passcode=candidate_challenge.encode()
        hash_value=hash_me(candidate_passcode,hashes.SHA256())
        if hash_value == hash_challenge:
            print(randnum)
            
            break
        randnum+=1
       
