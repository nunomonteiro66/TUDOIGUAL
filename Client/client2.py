import time
import requests
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from tkinter import *
import tkinter.messagebox as tkMessageBox
import os

#from file_cypher import encrypt_file, decrypt_file, gen_client_ECC_keys, loadPrivateKey, loadPublicKey, signFile
from file_cypher_rsa import encrypt_file, decrypt_file, signFile, genKeysRSA, loadPrivateKeyRSA, loadPublicKeyRSA

path = "client_keys"

isExist = os.path.exists(path)
if not isExist:
   os.makedirs(path)


root = Tk()
root.title("TUDOIGUAL - Sistema de Sincronização de Ficheiros Seguro")

width = 640
height = 480
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width / 2) - (width / 2)
y = (screen_height / 2) - (height / 2)
root.geometry("%dx%d+%d+%d" % (width, height, x, y))
root.resizable(0, 0)

# =======================================VARIABLES=====================================
credentials = {'username': StringVar(), 'password': StringVar()}


# Load the public key from file
with open('server-rsa-pk/public_key.pem', 'rb') as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

def Exit():
    result = tkMessageBox.askquestion('System', 'Are you sure you want to exit?', icon="warning")
    if result == 'yes':
        root.destroy()
        exit()

def LoginForm():
    global LoginFrame, lbl_result1
    LoginFrame = Frame(root)
    LoginFrame.pack(side=TOP, pady=80)
    lbl_username = Label(LoginFrame, text="Username:", font=('arial', 25), bd=18)
    lbl_username.grid(row=1)
    lbl_password = Label(LoginFrame, text="Password:", font=('arial', 25), bd=18)
    lbl_password.grid(row=2)
    lbl_result1 = Label(LoginFrame, text="", font=('arial', 18))
    lbl_result1.grid(row=3, columnspan=2)
    USERNAME = Entry(LoginFrame, font=('arial', 20), textvariable=credentials['username'], width=15)
    USERNAME.grid(row=1, column=1)
    PASSWORD = Entry(LoginFrame, font=('arial', 20), textvariable=credentials['password'], width=15, show="*")
    PASSWORD.grid(row=2, column=1)
    btn_login = Button(LoginFrame, text="Login", font=('arial', 18), width=35, command=Login)
    btn_login.grid(row=4, columnspan=2, pady=20)
    lbl_register = Label(LoginFrame, text="Register", fg="Blue", font=('arial', 12))
    lbl_register.grid(row=0, sticky=W)
    lbl_register.bind('<Button-1>', ToggleToRegister)

def RegisterForm():
    global RegisterFrame, lbl_result2
    RegisterFrame = Frame(root)
    RegisterFrame.pack(side=TOP, pady=40)
    lbl_username = Label(RegisterFrame, text="Username:", font=('arial', 18), bd=18)
    lbl_username.grid(row=1)
    lbl_password = Label(RegisterFrame, text="Password:", font=('arial', 18), bd=18)
    lbl_password.grid(row=2)
    lbl_result2 = Label(RegisterFrame, text="", font=('arial', 18))
    lbl_result2.grid(row=5, columnspan=2)
    USERNAME = Entry(RegisterFrame, font=('arial', 20), textvariable=credentials['username'], width=15)
    USERNAME.grid(row=1, column=1)
    PASSWORD = Entry(RegisterFrame, font=('arial', 20), textvariable=credentials['password'], width=15, show="*")
    PASSWORD.grid(row=2, column=1)
    btn_login = Button(RegisterFrame, text="Register", font=('arial', 18), width=35, command=Register)
    btn_login.grid(row=6, columnspan=2, pady=20)
    lbl_login = Label(RegisterFrame, text="Login", fg="Blue", font=('arial', 12))
    lbl_login.grid(row=0, sticky=W)
    lbl_login.bind('<Button-1>', ToggleToLogin)

def ToggleToLogin(event=None):
    RegisterFrame.destroy()
    LoginForm()

def ToggleToRegister(event=None):
    LoginFrame.destroy()
    RegisterForm()

def Login():
    url = 'http://127.0.0.1:5000/createNonce'
    parameters = {'key1': credentials['username'].get()}
    response = requests.post(url, data=parameters)

    nonce = response.text.encode('utf-8')
    if not os.path.exists('client_keys/client_private_key.pem'):
        gen_client_ECC_keys()
    with open('client_keys/client_private_key.pem', 'rb') as key_file:
        serialized_sk = key_file.read()
        
        private_key = serialization.load_pem_private_key(
            serialized_sk,
            password=None,
            #backend=default_backend()
        )
    """
    signature = private_key.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    """

    signature = private_key.sign(
        nonce,
        ec.ECDSA(hashes.SHA256())
    )

    url = 'http://127.0.0.1:5000/auth'
    parameters = {'key1': signature.decode('latin-1'), 'key2': credentials['username'].get()}
    response = requests.post(url, data=parameters)

    print(response.text)
    root.destroy() # fecha a janela de login, e continua com o programa (sincronizacao)

def Register():
    # encryptar dados com pk do server
    gen_client_ECC_keys()
    filePath = "fileDir"

    encrypted_username = public_key.encrypt(
        credentials['username'].get().encode('utf-8'),  # para encryptar dados tem de ser binario com utf-8
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_password = public_key.encrypt(
        credentials['password'].get().encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_path = public_key.encrypt(
        filePath.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # a encriptaçao cria os dados em binario com latin-1, e dá erro ao receber no server com este formato por isso dou decode antes de enviar para enviar a cifra com "string" em vez de "binario"
    parameters = {'key1': encrypted_username.decode('latin-1'), 'key2': encrypted_password.decode('latin-1'),
                  'key3': encrypted_path.decode('latin-1')}

    url = 'http://127.0.0.1:5000/registo'

    # enviar ficheiro da pk do user
    file_path = os.path.join(path, 'client_public_key.pem') # neste caso nao estou a enviar do user porque ainda não existe, mas aqui é para substituir por pk do user
    files = {'file': open(file_path, 'rb')}
    response = requests.post(url, files=files, data=parameters)

    print(response.text)

LoginForm()

# ========================================MENUBAR WIDGETS==================================
menubar = Menu(root)
root.config(menu=menubar)

# ========================================INITIALIZATION===================================
if __name__ == '__main__':
    root.mainloop()

    sk = loadPrivateKey()
    pk = loadPublicKey()

    #encrypt dos ficheiros da diretoria
    sync_path = "sync"
    if not os.path.exists(sync_path):
        os.makedirs(sync_path)
    allFiles1 = set(os.listdir(sync_path))
    while(True):
        allFiles2 = set(os.listdir(sync_path))
        if allFiles1 != allFiles2: #changes in the directory
            if(len(allFiles1) > len(allFiles2)): #a file was deleted
                for file in (allFiles1-allFiles2):
                    os.remove("./.signatures/"+file+".sig")
            else: #a file was added
                for file in (allFiles2-allFiles1):
                    print("FILE:" + file)
                    encrypt_file(os.path.join(sync_path, file), pk)
                    signFile(os.path.join(sync_path, file), sk)

            #ALERT THE SERVER
            
            allFiles1 = allFiles2

        time.sleep(10) #10 seconds
        #ask the server if there are any new files 