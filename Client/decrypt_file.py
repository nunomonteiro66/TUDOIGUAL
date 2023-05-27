import hashlib
import os
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter


class Enc():
    def __init__(self):
        #load the client public key
        self.client_pk = self.loadPublicKey(".client_keys")
        self.client_sk = self.loadPrivateKey(".client_keys")

        self.KEY_SIZE = 32 #bytes
        self.NONCE_SIZE = 16 #bytes
        self.CHUNK_SIZE = 200 #bytes

        self.keys_dir = ".keys"
        self.sync_dir = "sync"

    def AESkeyFromECC(self, pk):
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

    def loadPrivateKey(self, dir):
        print(dir)
        with open(dir+"/sk.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key

    def loadPublicKey(self, dir):
        with open(dir+"/pk.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key

    #encrypts the file with a random AES key, and then stores it in a KEY file
    def encryptFile(self, fileName):
        #generate random AES key
        AESkey = get_random_bytes(self.KEY_SIZE)
        print("Original AES key: ", AESkey.hex())
        nonce = get_random_bytes(self.NONCE_SIZE)
        print("Original nonce: ", nonce.hex())
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

        #cipher the file
        with open(fileName, 'rb') as inFile, open(fileName+".enc", 'wb') as outFile, open(os.path.join(self.keys_dir, fileName+".key"), 'wb') as keyFile:
            keyFile.write(nonce)
            keyFile.write(AESkey)

            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(cipher.encrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)

        #remove the original file
        os.remove(fileName)

        #remame file
        os.rename(fileName+".enc", fileName)

        #cipher the key file
        self.encrypt_key_file(fileName)

    #encrypts a KEY file with the client public key
    #ctpk = ephemeral key (CypherTextPublicKey)
    def encrypt_key_file(self, fileName):
        file = os.path.join(self.keys_dir, fileName+".key")


        #AES key for the KEY FILE
        ctpk, aeskey = self.AESkeyFromECC(self.client_pk)
        nonce = get_random_bytes(self.NONCE_SIZE) 
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(aeskey, AES.MODE_CTR, counter=counter)
        print("Original AES keyfile key: ", aeskey.hex())
        #encrypting file and storing in new file
        with open(file, 'rb') as inFile, open(file+".enc", 'wb') as outFile:
        
            #ctpk coordenates to bytes
            ctpk = ctpk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            print("Original ctpk: ", ctpk.hex())
            print("Original keyfile nonce: ", nonce.hex())
            outFile.write(nonce) #storing nonce (iv) in the beggining of the file
            outFile.write(ctpk) #storing ctpk in the beggining of the file        

            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(cipher.encrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)

        os.remove(file)

        os.rename(file+".enc", file)

    #decrypts a file using the AES key
    def decrypt_file(self, file):   
        #get the AES key from the KEY file
        with open(os.path.join(self.keys_dir, file+".key"), 'rb') as keyFile, open(os.path.join(self.keys_dir, file+".key.dec"), 'wb') as outFile:
            nonce = keyFile.read(self.NONCE_SIZE)
            print("ASdsadsada")
            print(nonce.hex())
            
            #ctpk
            byte_size = len(self.client_sk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            ctpk = keyFile.read(byte_size)
            ctpk = serialization.load_pem_public_key(ctpk)

            print("Derived ctpk: ", ctpk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).hex())
            print("Derived keyfile nonce: ", nonce.hex())
            #print(keyFile.read())
            #AES key
            AESkey = self.client_sk.exchange(ec.ECDH(), ctpk)
            #AES key
            AESkey = hashlib.sha256(AESkey)
            #AESkey.update(sharedECCkey_y.to_bytes(KEY_SIZE, byteorder='big'))
            AESkey = AESkey.digest()

            print("Derived AES keyfile key: ", AESkey.hex())
            counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

            
            byte = keyFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(decipher.decrypt(byte))
                byte = keyFile.read(self.CHUNK_SIZE)

        #remove the original file
        #os.remove(os.path.join(self.keys_dir, file+".key"))
        #print(AESkey.hex())
        #rename the deciphered file
        #os.rename(os.path.join(self.keys_dir, file+".key.dec"), os.path.join(self.keys_dir, file+".key"))
            
        #decrypting the actual file and storing in new file
        if not os.path.exists("dec"):
            os.makedirs("dec")
        with open(self.sync_dir+"/"+file, 'rb') as inFile, open("dec/"+file+".dec", 'wb') as outFile, open(os.path.join(self.keys_dir, file+".key.dec"), 'rb') as keyFile:
            #read the key and nonce from the file
            nonce = keyFile.read(self.NONCE_SIZE)
            AESkey = keyFile.read()

            print("Derived aes key: ", AESkey.hex())
            print("Derived nonce: ", nonce.hex())
            
            counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

            print("Starting decryption")
            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(decipher.decrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)
            print("Done!!")

        #print("Removing encrypted file")
        #os.remove(file)
        #print("Done!!")

        print("Renaming deciphered file")
        os.rename("dec/"+file+".dec", "dec/"+file)
        print("Done!!")

        #remove the dec key file
        os.remove(os.path.join(self.keys_dir, file+".key.dec"))


encclass = Enc()

for file in os.listdir("sync"):
    encclass.decrypt_file(file)