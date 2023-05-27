from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from Crypto.Util import Counter
from Crypto.Cipher import AES
import os, time
from cryptography.hazmat.primitives import serialization
import sys

def decrypt_file(self, file, key_file, sk):
        with open(key_file, 'rb') as f:
            nonce = f.read(self.NONCE_SIZE)
            encrypted_key = f.read()
    
        #decrypt key with sk
        key = sk.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    
        with open(file, 'rb') as f:
            data = f.read(self.CHUNK_SIZE)
            while data:
                ct = cipher.decrypt(data)
                #g.write(ct)
                data = f.read(self.CHUNK_SIZE)
        print(ct)
        
def loadPrivateKeyRSA(self,dir):
    with open(dir+"/sk_rsa.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key



if __name__ == "__main__":
    sk = loadPrivateKeyRSA(sys.argv[1])
    decrypt_file(sys.argv[2], sys.argv[3], sk)