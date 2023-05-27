import shutil
import time
from flask import Flask, request, jsonify, send_file, send_from_directory
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import bcrypt
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
import os
#from cyphers_util import decryptKey, loadClientPk, encryptKey, encryptZipFile, fileHash
from utils import decAndEnc, fileHash
from zipfile import ZipFile
import hashlib



app = Flask(__name__)

# create a database connection
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="1234",
    database="tudoigual"
)

mycursor = mydb.cursor()
executor = ThreadPoolExecutor()

# endpoint para verificar ficheiros em falta para cliente: necessita de username

#sends the name of the files missing in the user machine, so that he can ask them after
@app.route('/checkFiles', methods=['POST'])
def checkFiles():

    #delete tmp files
    for file in os.listdir(".tmp"):
        os.remove(".tmp/"+file)

    print('checkFiles')
    files_missing = []
    data = request.form
    for file in os.listdir('client_files'):
        
        users_missing = open('client_files/'+file, 'r').read().splitlines() #list of users that need to receive the file
        if(data['key1'] in users_missing): #user is missing the file
            files_missing.append(file) #add file to the list of files missing
            users_missing.remove(data['key1']) #remove user from the list of users missing the file
            with open('client_files/'+file, 'w') as f: f.write('\n'.join(users_missing)) #update the file
            continue #continue to next file
    print(files_missing)
    return '|'.join(files_missing)


#sends the requested file to the user
@app.route('/getFile', methods=['POST'])
def getFile():
    print("SENDING THE FILE TO THE USER")
    data = request.form
    file = data['key1'] #filename
    username = data['key2'] #username
    
    #decrypt the keyfile and encrypt it with the user public key
    decAndEnc(file, username)
    #create zip file
    with ZipFile(".tmp/"+file+".zip", 'w') as zipObj:
        zipObj.write(".tmp/"+file+".key", file+".key")
        zipObj.write("files/"+file, file)
        zipObj.write(".signatures/"+file+".sig", file+".sig")


    with ZipFile(".tmp/"+file+".zip", 'a') as zipObj:
        zipObj.writestr(".tmp/hash.txt", fileHash(".tmp/"+file+".zip").decode('latin-1'))
    
    #delete tmp files 
    os.remove(".tmp/"+file+".key")
    #os.remove(".tmp/"+file+".zip")

    #send the zip file
    return send_file(".tmp/"+file+".zip", as_attachment=True)
    


def sign_file(hash):

    with open('Ecc-keys/private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            #backend=default_backend()
        )

    # Sign the message with the private key
    signature = private_key.sign(
        hash,
        ec.ECDSA(hashes.SHA256())
    )

    # Return the signature as bytes
    return signature

# endpoint para enviar ficheiros do cliente para o servidor: necessita de filename, file, hash do file, chave para desencriptar por esta ordem, username


@app.route('/sendFile', methods=['POST'])
def sendFile():
    data = request.form

    file = request.files['file']
    keyfile = request.files['keyfile']

    file.save('files/' + data['key1'])

    # é necessário verificar o hash do ficheiro
    calculated_hash = fileHash(os.path.join('files', data['key1']))
    expected_hash = data['key3'].encode('latin-1')
    if calculated_hash == expected_hash:
        print("File hash verification successful.")
    else:
        print('File hash verification failed.')
        return

    # Save the file to a desired location on the server
    keyfile.save('files/'+data['key1']+".key")

    # é necessario calcular a assinatura do ficheiro pelo hash
    signature = sign_file(calculated_hash)

    print("====================================")
    print("Hash")
    print(calculated_hash)
    
    """
    #save the nounce and the decryption key
    with open('files/'+data['key1']+'.key', 'wb') as f:
        f.write(data['key6'].encode('latin-1')) #nounce
        f.write(data['key4'].encode('latin-1')) #ctpk

        #calculate the sharedkey
        private_key = serialization.load_pem_private_key(
            open('Ecc-keys/private_key.pem', 'rb').read(),
            password=None,
        )

        ctpk = serialization.load_pem_public_key(
            data['key4'].encode('latin-1'),
        )
        AESkey = private_key.exchange(ec.ECDH(), ctpk)
        AESkey = hashlib.sha256(AESkey)
        #AESkey.update(sharedECCkey_y.to_bytes(KEY_SIZE, byteorder='big'))
        AESkey = AESkey.digest()
        f.write(AESkey) #shared key
    

    print("Encrypted key with server")
    print(data['key4'].encode('latin-1'))    
    """
    # colocar ficheiro em falta para todos os users excepto no user que coloca o file

    #create file with the name of the file received
    if not os.path.isfile('client_files/'+data['key1']):
        file = open('client_files/'+data['key1'], 'w') 
    else:
        file = open('client_files/'+data['key1'], 'a')

    for filename in os.listdir('client_keys'):
        username = filename.split('pk')[0]
        if(username == data['key7']): #current user
            continue
        file.write(username) #wrtie the user as missing the file
        file.write('\n')
    file.close()

    #save signature
    with open(".signatures/"+data['key1']+".sig", 'wb') as sig_file:
        sig_file.write(signature)

    return signature.decode('latin-1')


def auth_user(signature, name):
    # ir buscar o nome da public key do user à bd
    sql = "SELECT public_key FROM users WHERE username = %s"
    val = (name,)
    mycursor.execute(sql, val)

    #print(str(mycursor.rowcount) + name)
    result = mycursor.fetchone()

    if result is not None:
        pk_name = result[0]

        # abrir pk do user da diretoria client_keys
        with open('client_keys/' + pk_name, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                #backend=default_backend()
            )

        # abrir e ler o nonce criado para a autenticação desse user da diretoria auth_nonce
        with open('auth_nonce/nonce' + name + '.txt', 'r') as file:
            # Read the contents of the file
            contents = file.read()

        # Convert the contents to an integer
        nonce = contents

        # verificar assinatura com pk do user
        print("Checking nonce signature")
        try:
            public_key.verify(
                signature,
                nonce.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return "1"  # Signature is valid
        except Exception as e:
            print(e)
            return "0" # Signature is invalid

    else:
        return "0"


# função para guardar registo na bd
def register_user(name, password, pk, path):
    sql = "SELECT COUNT(*) AS user_count FROM users WHERE username = %s"
    val = (name,)
    mycursor.execute(sql, val)
    result = mycursor.fetchone()

    if result[0] == 0:
        # criar salt para guardar representação de bd
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)

        sql = "INSERT INTO users (username, password, public_key, directory_path) VALUES (%s, %s,%s,%s)"
        val = (name, hashed_password.decode(), pk, path)
        mycursor.execute(sql, val)
        mydb.commit()

        if mycursor.rowcount == 1:
            file = open("client_files/"+name+".txt", 'w')
            file.close()
            return "Registo bem sucedido!"
        else:
            return "Erro. Registo não efetuado."
    else:
        return "Utilizador já existente."


# endpoint para autenticar (recebe username e assinatura do nonce)
@app.route('/auth', methods=['POST'])
def auth():
    data = request.form
    print("Atempting authentication")
    result = auth_user(data['key1'].encode('latin-1'), data['key2'])
    return result


# endpoint para receber nonce de autenticação (recebe o username)
@app.route('/createNonce', methods=['POST'])
def authNonce():
    data = request.form
    random_number = secrets.randbits(128)

    with open('auth_nonce/nonce' + data['key1'] + '.txt', 'w') as file:
        # Write the random number to the file
        file.write(str(random_number))

    return str(random_number)


@app.route('/registo', methods=['POST'])
def register():
    # receber dados
    data = request.form

    # abrir sk do server
    with open('Ecc-keys/private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    """
    # desencryptar com sk do server
    username = private_key.decrypt(
        # e temos de voltar a codificar para "binario" com latin-1
        data['key1'].encode('latin-1'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )"""
    username = data['key1']
    """
    password = private_key.decrypt(
        data['key2'].encode('latin-1'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    """
    password = data['key2']
    
    """
    path = private_key.decrypt(
        data['key3'].encode('latin-1'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    """
    path = data['key3']

    # receber o pk do user
    file = request.files['file']
    # o nome do ficheiro fica usernamepk.pem
    filename = username + 'pk.pem'
    # vai para a diretoria do server, na subdiretoria client_keys
    file.save('client_keys/' + filename)

    # enviar os dados para a função que guarda os dados na bd
    result = register_user(username, password, filename, path)
    return result


if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=True)
