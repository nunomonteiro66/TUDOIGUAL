import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend

# Load the public key from file
with open('server-pk/public_key.pem', 'rb') as public_key_file:
    public_key_pem = public_key_file.read()
    public_key = serialization.load_pem_public_key(public_key_pem)

username = "Diogo"
password = "teste123"
path = "myDir"


url = 'http://127.0.0.1:5000/regist'
file_path = 'server-pk/public_key.pem'
parameters = {'key1': username, 'key2': password, 'key3':path}

files = {'file': open(file_path, 'rb')}
response = requests.post(url, files=files, data=parameters)

print(response.text)