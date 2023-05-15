from flask import Flask, request, jsonify, send_file
import mysql.connector
from concurrent.futures import ThreadPoolExecutor
import bcrypt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend


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

def register_user(name, password,pk,path):
    

    '''# Load the private key from file
    with open('Ecc-keys/private_key.pem', 'rb') as private_key_file:
        private_key_pem = private_key_file.read()
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Decrypt the ciphertext using the private key
    u_name = private_key.decrypt(
        name,
        ec.ECIES(algorithm=ec.BrainpoolP256R1(), hash_algorithm=hashes.SHA256())
    )

    u_pwd = private_key.decrypt(
        password,
        ec.ECIES(algorithm=ec.BrainpoolP256R1(), hash_algorithm=hashes.SHA256())
    )

    u_path = private_key.decrypt(
        path,
        ec.ECIES(algorithm=ec.BrainpoolP256R1(), hash_algorithm=hashes.SHA256())
    )'''


    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    sql = "INSERT INTO users (username, password, public_key, directory_path) VALUES (%s, %s,%s,%s)"
    val = (name, hashed_password,pk,path)
    mycursor.execute(sql, val)
    mydb.commit()
    if mycursor.rowcount == 1:
        return "1"
    else:
        return "0"

@app.route('/regist', methods=['POST'])
def register():
    data = request.form
    file = request.files['file']
    filename = data['key1']+'pk.pem'
    file.save('client_keys/'+filename)
    
    result = register_user(data['key1'], data['key2'],filename,data['key3'])
    return result


if __name__ == '__main__':
    app.run(debug=True)