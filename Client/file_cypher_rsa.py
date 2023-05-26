import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
class EncryptionClass():

    def __init__(self, globalValues):
        self.sync_dir = globalValues['sync_dir']
        self.server_pk = self.loadPublicKeyRSA(globalValues['server_keys'])
        if not os.path.isfile(globalValues['client_keys']+'/sk_rsa.pem'):
            self.client_sk, self.client_pk = self.genKeysRSA(globalValues['client_keys'])
        else:
            self.client_sk = self.loadPrivateKeyRSA(globalValues['client_keys'])
            self.client_pk = self.loadPublicKeyRSA(globalValues['client_keys'])
        self.keys_dir = globalValues['keys_dir']
        #values for encryption

        self.KEY_SIZE = 32 #bytes
        self.NONCE_SIZE = 16 #bytes
        self.CHUNK_SIZE = 2000 #bytes

    #generates a RSA key pair, and saves it to a file
    #returns the private and public keys
    def genKeysRSA(self, keys_directory):
    
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()

        with open(keys_directory+'/sk_rsa.pem', 'wb') as sk_file, open(keys_directory+'/pk_rsa.pem', 'wb') as pk_file:
            sk_serialized = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption() #!!!!!!!!!!!!!!!!!!!!!!!!!
            )
            pk_serialized = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                #encryption_algorithm=serialization.NoEncryption()
            )
       
            sk_file.write(sk_serialized)
            pk_file.write(pk_serialized)


        return private_key, public_key

    def loadPrivateKeyRSA(self,dir):
        with open(dir+"/sk_rsa.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key

    def loadPublicKeyRSA(self,dir):
        with open(dir+"/pk_rsa.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key


    #===============================================================================

    #-----------------AES-----------------
    #derives a AES key from the public key

    def encrypt_file(self, file):
        print("ENCRYPTING THE FILE")
        nonce = get_random_bytes(self.NONCE_SIZE)
        counter = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
        key = get_random_bytes(self.KEY_SIZE)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        print("=======================")
        print("Original key")
        print(key)

        with open(os.path.join(self.sync_dir, file), 'rb') as f, open(os.path.join(self.sync_dir, file + '.enc'), 'wb') as g:
            data = f.read(self.CHUNK_SIZE)
            while data:
                ct = cipher.encrypt(data)
                g.write(ct)
                data = f.read(self.CHUNK_SIZE)
    
        #encrypt key with pk
        encrypted_key = self.client_pk.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        #write to file
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
        with open(self.keys_dir+'/'+file+".key", 'wb') as f:
            f.write(nonce)
            f.write(encrypted_key)

        #delete original and rename encrypted file
        os.remove(os.path.join(self.sync_dir, file))
        os.rename(os.path.join(self.sync_dir, file + '.enc'), os.path.join(self.sync_dir, file))
    


    def decrypt_file(self, file, key_file, sk):
        with open(os.path.join(self.keys_dir, key_file), 'rb') as f:
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
    
        with open(os.path.join(self.sync_dir, file), 'rb') as f, open(os.path.join(self.sync_dir, file) + '.dec', 'wb') as g:
            data = f.read(self.CHUNK_SIZE)
            while data:
                ct = cipher.decrypt(data)
                g.write(ct)
                data = f.read(self.CHUNK_SIZE)

        #rename file
        os.remove(os.path.join(self.sync_dir, file))
        time.sleep(0.5)
        os.rename(os.path.join(self.sync_dir, file + '.dec'), os.path.join(self.sync_dir, file))

    #decrypts and re-encrypts the key with the server's public key
    #returns the re-encrypted key and the nounce
    def serverEncrypt(self, file):
        print("ENCRYPTING WITH THE SERVER'S PUBLIC KEY")
        original_key_file = os.path.join(self.keys_dir, file+".key")

        with open(original_key_file, 'rb') as original:
            nonce = original.read(self.NONCE_SIZE)
            encrypted_key = original.read()

            decrypted_key = self.client_sk.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("Original key")
            print(decrypted_key)
            encrypted_key = self.server_pk.encrypt(
                decrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            print("ENCRYPTED KEY WITH SERVER")
            print(encrypted_key)
           

        return nonce, encrypted_key


    #-------------------------------------

    """
    #FOR THE SERVER
    def signFile(self, file, signature_dir, sk):
        with open(file, 'rb') as f, open(signature_dir+'/'+file+'.sig', 'wb') as sig_file:
            data = f.read(self.CHUNK_SIZE)
            while data:
                signature = sk.sign(
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                sig_file.write(signature)
                data = f.read(self.CHUNK_SIZE)
    """

    def checkSignature(self, file, sig_file):
        print("CHECKING SIGNATURE")
        print(file)
        print(sig_file)
        with open(sig_file, 'rb') as sig_file:
            signature = sig_file.read()
            hash = self.fileHash(file)
            print(hash)
            try:
                self.server_pk.verify(
                    signature,
                    hash,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                print(e)
                return False
                
            return True

    def fileHash(self,file):
        print("HASHING THE FILE")
        with open(os.path.join(self.sync_dir, file), 'rb') as f:
            data = f.read(self.CHUNK_SIZE)
            hash = hashes.Hash(hashes.SHA256())
            while data:
                hash.update(data)
                data = f.read(self.CHUNK_SIZE)
            return hash.finalize()
        



