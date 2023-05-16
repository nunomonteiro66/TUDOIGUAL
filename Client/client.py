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



url = 'http://127.0.0.1:5000/regist'

#enviar ficheiro da pk do user
file_path = 'server-pk/public_key.pem' #neste caso nao estou a enviar do user porque ainda não existe, mas aqui é para substituir por pk do user
files = {'file': open(file_path, 'rb')}
response = requests.post(url, files=files, data=parameters)

print(response.text)
