from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


KEY_SIZE = 32 #bytes
NONCE_SIZE = 16 #bytes
CHUNK_SIZE = 2000 #bytes

#decrypts the file with the symetric key and the nonce
#returns the nounce and the key
def decryptKey(file):
    sk = loadServerSk()
    key_file = "files/"+file+".key"
    with open(key_file, 'rb') as key:
        nonce = key.read(NONCE_SIZE)
        encrypted_key = key.read()

        decrypted_key = sk.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return nonce, decrypted_key

def encryptKey(decrypt_key, pk):
    encrypted_key = pk.encrypt(
        decrypt_key,
        padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
    )
    return encrypted_key



def loadServerSk():
    with open('RSA-keys/private_key.pem', 'rb') as key_file:
        sk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return sk

def loadClientPk(username):
    print("------------------")
    print(username+"pk.pem")
    with open('client_keys/'+username+'pk.pem', 'rb') as key_file:
        pk = serialization.load_pem_public_key(
            key_file.read(),
        )
    return pk

#returns the bytes corresponding to the zip file encrypted
def encryptZipFile(zipFile, pk):
    encrypted = pk.encrypt(
        zipFile,
        padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
    )

    return encrypted


def fileHash(file):
        print("HASHING THE FILE")
        with open(file, 'rb') as f:
            data = f.read(CHUNK_SIZE)
            hash = hashes.Hash(hashes.SHA256())
            while data:
                hash.update(data)
                data = f.read(CHUNK_SIZE)
            return hash.finalize()