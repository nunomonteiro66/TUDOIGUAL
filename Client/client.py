import requests
from cryptography.hazmat.primitives.asymmetric import ec,padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
import json

# Load the public key from file
with open('server-rsa-pk/public_key.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

#parametros para registo
username = "DiogoV"
password = "teste456"
path = "myDir"

#encryptar dados com pk do server
encrypted_username = public_key.encrypt(
    username.encode('utf-8'), #para encryptar dados tem de ser binario com utf-8
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

encrypted_password = public_key.encrypt(
    password.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

encrypted_path = public_key.encrypt(
    path.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# a encriptaçao cria os dados em binario com latin-1, e dá erro ao receber no server com este formato por isso dou decode antes de enviar para enviar a cifra com "string" em vez de "binario"
parameters = {'key1': encrypted_username.decode('latin-1'), 'key2': encrypted_password.decode('latin-1'), 'key3':encrypted_path.decode('latin-1')}


#descomentar para testar registo
'''url = 'http://127.0.0.1:5000/regist'

#enviar ficheiro da pk do user
file_path = 'server-rsa-pk/public_key.pem' #neste caso nao estou a enviar do user porque ainda não existe, mas aqui é para substituir por pk do user
files = {'file': open(file_path, 'rb')}
response = requests.post(url, files=files, data=parameters)'''

#descomentar para testar authenticação
'''
url = 'http://127.0.0.1:5000/authNonce'
parameters = {'key1': "DiogoV"}
response = requests.post(url, data=parameters)

print(response.text)

with open('../Server/RSA-keys/private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

signature = private_key.sign(
        response.text.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

url = 'http://127.0.0.1:5000/auth'
parameters = {'key1':signature.decode('latin-1'),'key2': "DiogoV"}
response = requests.post(url, data=parameters)

print(response.text)'''


