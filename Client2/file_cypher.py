import hashlib
import os
import shutil
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

class EncryptionClass:

    def __init__(self, globalValues):
        self.sync_dir = globalValues['sync_dir']
        self.server_pk = self.loadPublicKey(globalValues['server_keys'])
        if not os.path.isfile(globalValues['client_keys']+'/sk.pem'):
            self.client_sk, self.client_pk = self.gen_client_ECC_keys(globalValues['client_keys'])
        else:
            self.client_sk = self.loadPrivateKey(globalValues['client_keys'])
            self.client_pk = self.loadPublicKey(globalValues['client_keys'])
        self.keys_dir = globalValues['keys_dir']
        #values for encryption

        self.KEY_SIZE = 32 #bytes
        self.NONCE_SIZE = 16 #bytes
        self.CHUNK_SIZE = 2000 #bytes

    #-----------------ECC-----------------


    def gen_client_ECC_keys(self, keys_directory):
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key()
        with open(keys_directory+'/sk.pem', 'wb') as f, open(keys_directory+'/pk.pem', 'wb') as g:
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
        return sk, pk



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

    #-------------------------------------

    #-----------------AES-----------------
    #derives a AES key from the public key
    #(sk * G) * ctsk = ctpk * sk = SharedSecret
    #pk * ctsk = ctpk * sk = SharedSecret
    #ctpk = ephemeral key (CypherTextPublicKey)
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

    #encrypts the file with a random AES key, and then stores it in a KEY file
    def encrypt_file(self, fileName):
        #generate random AES key
        AESkey = get_random_bytes(self.KEY_SIZE)
        nonce = get_random_bytes(self.NONCE_SIZE)
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

        #cipher the file
        with open(os.path.join(self.sync_dir, fileName), 'rb') as inFile, open(os.path.join(self.sync_dir, fileName+".enc"), 'wb') as outFile, open(os.path.join(self.keys_dir, fileName+".key"), 'wb') as keyFile:
            keyFile.write(nonce)
            keyFile.write(AESkey)

            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(cipher.encrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)

        #remove the original file
        os.remove(os.path.join(self.sync_dir, fileName))

        #remame file
        os.rename(os.path.join(self.sync_dir, fileName+".enc"), os.path.join(self.sync_dir, fileName))

        #cipher the key file
        self.encrypt_key_file(os.path.join(self.keys_dir, fileName+".key"), self.client_pk)

    #encrypts a KEY file with the client public key
    #ctpk = ephemeral key (CypherTextPublicKey)
    def encrypt_key_file(self, keyFile, pk):


        #AES key for the KEY FILE
        ctpk, aeskey = self.AESkeyFromECC(pk)
        nonce = get_random_bytes(self.NONCE_SIZE) 
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        cipher = AES.new(aeskey, AES.MODE_CTR, counter=counter)
    
        #encrypting file and storing in new file
        with open(keyFile, 'rb') as inFile, open(keyFile+".enc", 'wb') as outFile:
        
            #ctpk coordenates to bytes
            ctpk = ctpk.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
            outFile.write(nonce) #storing nonce (iv) in the beggining of the file
            outFile.write(ctpk) #storing ctpk in the beggining of the file        

            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(cipher.encrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)
        print("Done!!")

        print("Removing deciphered file")
        os.remove(keyFile)
        print("Done!!")

        print("Renaming encrypted file")
        os.rename(keyFile+".enc", keyFile)
        print("Done!!")

       

        return nonce, ctpk

    #decrypts a file using the AES key
    def decrypt_file(self, file):   
        keyfile = os.path.join(self.keys_dir, file+".key")
        AESkey = self.decrypt_keyfile(keyfile)
            
        #decrypting the actual file and storing in new file
        with open(file, 'rb') as inFile, open(file+".dec", 'wb') as outFile, open(os.path.join(self.keys_dir, file+".key"), 'rb') as keyFile:
            #read the key and nonce from the file
            nonce = keyFile.read(self.NONCE_SIZE)
            AESkey = keyFile.read()
            
            counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

            print("Starting decryption")
            byte = inFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(decipher.decrypt(byte))
                byte = inFile.read(self.CHUNK_SIZE)
            print("Done!!")

        print("Removing encrypted file")
        os.remove(file)
        print("Done!!")

        print("Renaming deciphered file")
        os.rename(file+".dec", file)
        print("Done!!")
    

    #--------------signature-------------------
    def signFile(self, file):
        if not os.path.isdir("./.signatures"):
            os.mkdir("./.signatures")
        filename = file.split("\\")[-1]
        with open(file, "rb") as f, open("./.signatures/"+filename+".sig", "wb") as sig:
            signature = self.client_sk.sign(
                f.read(), 
                ec.ECDSA(hashes.SHA256())
            )
            sig.write(signature)

    #verifies if the signature is valid, with the pk of the server
    def checkSignature(self, file,signature):
        with open(signature, "rb") as sig:
            hash = self.fileHash(file)
            try:
                self.server_pk.verify(
                    sig.read(), 
                    hash, 
                    ec.ECDSA(hashes.SHA256())
                )
                return True
            except Exception as e:
                print(e)
                return False
    
    def decrypt_keyfile(self, keyfile_dir):
        #get the AES key from the KEY file
        with open(keyfile_dir, 'rb') as keyFile, open(keyfile_dir+'.dec', 'wb') as outFile:
            nonce = keyFile.read(self.NONCE_SIZE)
            
            #ctpk
            byte_size = len(self.client_sk.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            ctpk = keyFile.read(byte_size)
            ctpk = serialization.load_pem_public_key(ctpk)

            #AES key
            AESkey = self.client_sk.exchange(ec.ECDH(), ctpk)
            AESkey = hashlib.sha256(AESkey)
            AESkey = AESkey.digest()

            counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
            decipher = AES.new(AESkey, AES.MODE_CTR, counter=counter)

            
            byte = keyFile.read(self.CHUNK_SIZE)
            while byte:
                outFile.write(decipher.decrypt(byte))
                byte = keyFile.read(self.CHUNK_SIZE)

        #remove the original file
        os.remove(keyfile_dir)

        #rename the deciphered file
        os.rename(keyfile_dir+'.dec', keyfile_dir)

        return AESkey
            

    #decrypts and then encrypts the key file with the server pk
    def serverEncrypt(self, file):

        #copy file to tmp folder
        shutil.copy(os.path.join(self.keys_dir, file+".key"), "./.tmp/"+file+".key")

        #decrypt file in tmp folder
        self.decrypt_keyfile("./.tmp/"+file+".key")

        #encrypt file in tmp folder with server pk
        nonce, ctpk = self.encrypt_key_file("./.tmp/"+file+".key", self.server_pk)

        

        return nonce, ctpk
    


    def fileHash(self,file):
        print("HASHING THE FILE")
        with open(os.path.join(self.sync_dir, file), 'rb') as f:
            data = f.read(self.CHUNK_SIZE)
            hash = hashes.Hash(hashes.SHA256())
            while data:
                hash.update(data)
                data = f.read(self.CHUNK_SIZE)
            return hash.finalize()

