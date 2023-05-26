import hashlib
import os
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

KEY_SIZE = 32 #bytes
NONCE_SIZE = 16 #bytes
CHUNK_SIZE = 2000 #bytes

def getPrivateKey():
    with open('ECC-keys/private_key.pem', 'rb') as key_file:
        sk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return sk
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

#encrypts a KEY file with the client public key
#ctpk = ephemeral key (CypherTextPublicKey)
def encrypt_key_file(keyFile, pk):


    #AES key for the KEY FILE
    ctpk, aeskey = AESkeyFromECC(pk)
    nonce = get_random_bytes(NONCE_SIZE) 
    counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
    cipher = AES.new(aeskey, AES.MODE_CTR, counter=counter)
    
    #encrypting file and storing in new file
    with open(keyFile, 'rb') as inFile, open(keyFile+".enc", 'wb') as outFile:
        
        #ctpk coordenates to bytes
        ctpk = ctpk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
        outFile.write(nonce) #storing nonce (iv) in the beggining of the file
        outFile.write(ctpk) #storing ctpk in the beggining of the file        

        byte = inFile.read(CHUNK_SIZE)
        while byte:
            outFile.write(cipher.encrypt(byte))
            byte = inFile.read(CHUNK_SIZE)

    os.remove(keyFile)

    os.rename(keyFile+".enc", keyFile)

    

    return nonce, ctpk


#decrypts the keyfile and encrypts it with the public key of the user
def decrypt_keyfile(file):
    

    

    sk = getPrivateKey() #sk of the server
    
    #decrypt the file in tmp folder
    with open(file, 'rb') as keyFile, open(file+".dec", 'wb') as outFile:
            nonce = keyFile.read(NONCE_SIZE)
            
            #ctpk
            byte_size = len(sk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            ctpk = keyFile.read(byte_size)
            ctpk = serialization.load_pem_public_key(ctpk)

            #AES key
            AESkey = sk.exchange(ec.ECDH(), ctpk)
            AESkey = hashlib.sha256(AESkey)
            AESkey = AESkey.digest()

            counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

            
            byte = keyFile.read(CHUNK_SIZE)
            while byte:
                outFile.write(decipher.decrypt(byte))
                byte = keyFile.read(CHUNK_SIZE)
        
    #remove the original file
    os.remove(file)

    #rename the deciphered file
    os.rename(file+".dec", file)

    


def decAndEnc(file, user):

    #copy file to tmp folder
    shutil.copyfile(os.path.join('files', file+".key"), os.path.join(".tmp", file+".key"))
    
    #decrypt file in tmp folder
    decrypt_keyfile("./.tmp/"+file+".key")

    #encrypt file in tmp folder
    user_pk = loadClientPk(user)
    encrypt_key_file("./.tmp/"+file+".key", user_pk)

def loadClientPk(username):
    print("------------------")
    print(username+"pk.pem")
    with open('client_keys/'+username+'pk.pem', 'rb') as key_file:
        pk = serialization.load_pem_public_key(
            key_file.read(),
        )
    return pk


def fileHash(file):
        print("HASHING THE FILE")
        with open(file, 'rb') as f:
            data = f.read(CHUNK_SIZE)
            hash = hashes.Hash(hashes.SHA256())
            while data:
                hash.update(data)
                data = f.read(CHUNK_SIZE)
            return hash.finalize()