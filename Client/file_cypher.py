import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY_SIZE = 32 #bytes
NONCE_SIZE = 16 #bytes
CHUNK_SIZE = 2000 #bytes

#-----------------ECC-----------------


def gen_client_ECC_keys():
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    with open('client_keys/client_private_key.pem', 'wb') as f, open('client_keys/client_public_key.pem', 'wb') as g:
        sk_serialized = sk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() #!!!!!!!!!!!!!!!!!!!!!!!!!
        )
        pk_serialized = pk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            #encryption_algorithm=serialization.NoEncryption()
        )
       
        f.write(sk_serialized)
        g.write(pk_serialized)



def loadPrivateKey():
    with open("client_keys/client_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def loadPublicKey():
    with open("client_keys/client_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

#-------------------------------------

#-----------------AES-----------------
#derives a AES key from the public key
#(sk * G) * ctsk = ctpk * sk = SharedSecret
#pk * ctsk = ctpk * sk = SharedSecret
#ctpk = ephemeral key (CypherTextPublicKey)
def AESkeyFromECC(pk):
    #ctsk
    ctsk = ec.generate_private_key(ec.SECP256R1())
    ctpk = ctsk.public_key()
    sharedECCkey = ctsk.exchange(ec.ECDH(), pk)


    #AES key
    AESkey = hashlib.sha256(sharedECCkey)
    #AESkey.update(sharedECCkey_y.to_bytes(KEY_SIZE, byteorder='big'))
    AESkey = AESkey.digest()

    #encrypt
    return ctpk, AESkey


#encrypts a file using AES key
#ctpk = ephemeral key (CypherTextPublicKey)
def encrypt_file(fileName, pk):
    
    print("Deriving AES key from ECC key")
    ctpk, aeskey = AESkeyFromECC(pk)
    print("Done!!")
    
    nonce = get_random_bytes(NONCE_SIZE) 
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    cipher = AES.new(aeskey, AES.MODE_CTR, counter=counter)
    
    print("Starting encryption")
    #encrypting file and storing in new file
    with open(fileName, 'rb') as inFile, open(fileName + ".aes", 'wb') as outFile:
        
        #ctpk coordenates to bytes
        ctpk = ctpk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        outFile.write(ctpk) #storing ctpk in the beggining of the file        
    

        outFile.write(nonce) #storing nonce (iv) in the beggining of the file
        
        byte = inFile.read(CHUNK_SIZE)
        while byte:
            outFile.write(cipher.encrypt(byte))
            byte = inFile.read(CHUNK_SIZE)
    print("Done!!")

    print("Removing deciphered file")
    os.remove(fileName)
    print("Done!!")

    print("Renaming encrypted file")
    os.rename(fileName + ".aes", fileName)
    print("Done!!")

#decrypts a file using the AES key
def decrypt_file(filename, sk):   
    with open(filename, 'rb') as inFile, open(filename+".dec", 'wb') as outFile:
        
        #get the size of the public key in bytes
        byte_size = len(sk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        #ctpk coordenates from file (in bytes)
        ctpk = inFile.read(byte_size)
        ctpk = serialization.load_pem_public_key(ctpk)
        

        sharedECCkey = sk.exchange(ec.ECDH(), ctpk)

       
        #AES key
        AESkey = hashlib.sha256(sharedECCkey)
        AESkey = AESkey.digest()


        nonce = inFile.read(NONCE_SIZE)
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

        print("Starting decryption")
        byte = inFile.read(CHUNK_SIZE)
        while byte:
            outFile.write(decipher.decrypt(byte))
            byte = inFile.read(CHUNK_SIZE)
        print("Done!!")

    print("Removing encrypted file")
    os.remove(filename)
    print("Done!!")

    print("Renaming deciphered file")
    os.rename(filename + ".dec", filename)
    print("Done!!")
    

#--------------signature-------------------
def signFile(file, sk):
    if not os.path.isdir("./.signatures"):
        os.mkdir("./.signatures")
    filename = file.split("\\")[-1]
    with open(file, "rb") as f, open("./.signatures/"+filename+".sig", "wb") as sig:
        signature = sk.sign(f.read(), ec.ECDSA(hashes.SHA256()))
        sig.write(signature)

def verifySignature(file,signature, pk):
    with open(file, "rb") as f, open(signature, "rb") as sig:
        try:
            pk.verify(sig.read(), f.read(), ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False



with open("test.txt", "w") as f:
    f.write("Hello World!")

sk = loadPrivateKey()
pk = loadPublicKey()

encrypt_file("test.txt", pk)
decrypt_file("test.txt", sk)
