from flask import Flask, request, jsonify, send_file
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import bcrypt
from cryptography.hazmat.primitives.asymmetric import ec,padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
import secrets
import json


app = Flask(__name__)


# create a database connection
mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="tudoigual"
)

mycursor = mydb.cursor()
executor = ThreadPoolExecutor()

def auth_user(signature,name):

    sql = "SELECT public_key FROM `users` WHERE username = %s"
    val = (name,)
    mycursor.execute(sql, val)

    if mycursor.rowcount == 1:
        result = mycursor.fetchone()
        pk_name = result[0]

        with open('client_keys/'+pk_name+'.pem', 'rb') as key_file:
            public_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        with open('auth_nonce/nonce'+name+'random_number.txt', 'r') as file:
            # Read the contents of the file
            contents = file.read()

        # Convert the contents to an integer
        nonce = int(contents)
        
        try:
            public_key.verify(
                signature,
                nonce,
                padding.PKCS1v15(),
                public_key.signing_algorithm
            )
            return True  # Signature is valid
        except Exception:
            return False  # Signature is invalid

    else:
        return "0"
    

#função para guardar registo na bd
def register_user(name, password,pk,path):

    sql = "SELECT COUNT(*) AS user_count FROM users WHERE username = %s"
    val = (name,)
    mycursor.execute(sql, val)
    result = mycursor.fetchone()
    
    if result[0] == 0:
        #criar salt para guardar representação de bd
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)

        sql = "INSERT INTO users (username, password, public_key, directory_path) VALUES (%s, %s,%s,%s)"
        val = (name, hashed_password.decode(),pk,path)
        mycursor.execute(sql, val)
        mydb.commit()
        
        if mycursor.rowcount == 1:
            return "1"
        else:
            return "0"
    else:
        return "0"

    
#endpoint para autenticar (recebe username e assinatura do nonce)
@app.route('/auth', methods=['POST'])
def auth():
    data = request.form
    
    
    result = auth_user(data['key1'],data['key2'])
    return result   

#endpoint para receber nonce de autenticação (recebe o username)
@app.route('/authNonce', methods=['POST'])
def auth():
    data = request.form
    random_number = secrets.randbits(128)

    with open('nonce'+data['key1']+'.txt', 'w') as file:
        # Write the random number to the file
        file.write(str(random_number))


    return random_number

@app.route('/regist', methods=['POST'])
def register():
    #receber dados
    data = request.form

    #abrir sk do server
    with open('RSA-keys/private_key.pem', 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    #desencryptar com sk do server
    username = private_key.decrypt(
        data['key1'].encode('latin-1'), # e temos de voltar a codificar para "binario" com latin-1 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    password = private_key.decrypt(
        data['key2'].encode('latin-1'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    path = private_key.decrypt(
        data['key3'].encode('latin-1'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #receber o pk do user
    file = request.files['file']
    #o nome do ficheiro fica usernamepk.pem
    filename = username.decode('utf-8')+'pk.pem'
    #vai para a diretoria do server, na subdiretoria client_keys
    file.save('client_keys/'+filename)
    
    #enviar os dados para a função que guarda os dados na bd
    result = register_user(username.decode('utf-8'), password.decode('utf-8'),filename,path.decode('utf-8'))
    return result
    return "0"

if __name__ == '__main__':
    app.run(debug=True)