import shutil
import time
import requests
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from tkinter import *
import tkinter.messagebox as tkMessageBox
import os
import json

#from file_cypher import encrypt_file, decrypt_file, gen_client_ECC_keys, loadPrivateKey, loadPublicKey, signFile
from file_cypher_rsa import EncryptionClass
import zipfile


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
globalValues = {
    'username': "", 
    'password': "",
    'sync_dir': "",
    'server_keys': "",
    'signature_dir': "",
    'client_keys': "",
    'keys_dir': ""
    }

client_sk = None
client_pk = None
server_pk = None

#default configurations
def MakeConfigFile():
    globalValues['username'] = 'client_asdasdsadsad'
    globalValues['password'] = '1234'
    globalValues['sync_dir'] = 'sync'
    globalValues['server_keys'] = './.server_keys'
    globalValues['signature_dir'] = './.signatures'
    globalValues['client_keys'] = './.client_keys'
    globalValues['keys_dir'] = './.keys'
    with open("config.txt", "w") as f:
        json.dump(globalValues, f)

    #create directories
    if not os.path.exists(globalValues['server_keys']):
        os.makedirs(globalValues['server_keys'])
    if not os.path.exists(globalValues['signature_dir']):
        os.makedirs(globalValues['signature_dir'])
    if not os.path.exists(globalValues['client_keys']):
        os.makedirs(globalValues['client_keys'])
    if not os.path.exists(globalValues['keys_dir']):
        os.makedirs(globalValues['keys_dir'])
    if not os.path.exists(globalValues['sync_dir']):
        os.makedirs(globalValues['sync_dir'])

    



def LoadConfigFile():
    global globalValues
    with open("config.txt", "r") as f:
        globalValues = json.load(f)

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
    USERNAME = Entry(LoginFrame, font=('arial', 20), textvariable=globalValues['username'], width=15)
    USERNAME.grid(row=1, column=1)
    PASSWORD = Entry(LoginFrame, font=('arial', 20), textvariable=globalValues['password'], width=15, show="*")
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
    USERNAME = Entry(RegisterFrame, font=('arial', 20), textvariable=globalValues['username'], width=15)
    USERNAME.grid(row=1, column=1)
    PASSWORD = Entry(RegisterFrame, font=('arial', 20), textvariable=globalValues['password'], width=15, show="*")
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

def Authentication():
    url = 'http://127.0.0.1:5000/createNonce'
    parameters = {'key1': globalValues['username']}
    response = requests.post(url, data=parameters) #nonce do servidor

    nonce = response.text.encode('utf-8')

    signature = client_sk.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    url = 'http://127.0.0.1:5000/auth'
    parameters = {'key1': signature.decode('latin-1'), 'key2': globalValues['username']}
    response = requests.post(url, data=parameters) #envia a assinatura para verificacao
    return response.text #1 se autenticado, 0 se nao autenticado

def Login():
    url = 'http://127.0.0.1:5000/createNonce'
    parameters = {'key1': globalValues['username']}
    response = requests.post(url, data=parameters)

    nonce = response.text.encode('utf-8')
    if not os.path.exists('client_keys/client_private_key.pem'):
        #gen_client_ECC_keys()
        Encclass.genKeysRSA()
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
    parameters = {'key1': signature.decode('latin-1'), 'key2': globalValues['username']}
    response = requests.post(url, data=parameters)

    print(response.text)
    root.destroy() # fecha a janela de login, e continua com o programa (sincronizacao)

def Register():
    # encryptar dados com pk do server
    #gen_client_ECC_keys()
    global client_sk, client_pk, server_pk
    client_sk, client_pk = Encclass.client_sk, Encclass.client_pk
    
    #load server public key
    server_pk = Encclass.server_pk

    #encrypt the username and password with the server's public key
    encrypted_username = server_pk.encrypt(
        globalValues['username'].encode('utf-8'),  # para encryptar dados tem de ser binario com utf-8
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    
    encrypted_password = server_pk.encrypt(
        globalValues['password'].encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    

    encrypted_path = server_pk.encrypt(
        globalValues['sync_dir'].encode('utf-8'),
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
    files = {'file': open(globalValues['client_keys']+'/pk_rsa.pem', 'rb')}
    response = requests.post(url, files=files, data=parameters)

    print(response.text)

#envia o ficheiro para o servidor
#devolve a assinatura do ficheiro por parte do servidor
def sendFile(file):
    if(Authentication() != "1"):
        print("Authentication failed")
        return
    
    #create a copy of the key file, desencrypt and encrypt it with the pk of the server
    nonce, encrypted_key = Encclass.serverEncrypt(file)
    
    url = 'http://127.0.0.1:5000/sendFile'
    file_full_path = os.path.join(globalValues['sync_dir'],file)
    data = {
        'key1': file, 
        'key2': open(file_full_path, 'rb').read(),
        #'key3': Encclass.fileHash(file).decode('latin-1'),
        'key4': encrypted_key.decode('latin-1'),
        'key5': globalValues['username'],
        'key6': nonce.decode('latin-1'),
        'key7': globalValues['username']
        }

    #print(nonce)
    
    #print(str(encrypted_key))
    response = requests.post(url, data=data, files={'file':open(file_full_path, 'rb')}) #!!!!! Two times file sent!!
    
    return response.text.encode('latin-1') #signature of the file

def checkNewFilesInServer():
    url = 'http://127.0.0.1:5000/checkFiles'
    data = {'key1': globalValues['username']}
    response = requests.post(url, data=data)
    files_missing = response.text.split('|')
    if(files_missing[0] == ""):
        return
    for file in files_missing:
        #get the zip file
        url = 'http://127.0.0.1:5000/getFile'
        data = {'key1': file, 'key2': globalValues['username']}
        response = requests.post(url, data=data)
        #save zip
        with open(globalValues['sync_dir']+"/"+file+".zip", 'wb') as f:
            f.write(response.content)
        

        #unzip file
        with zipfile.ZipFile(globalValues['sync_dir']+"/"+file+".zip", 'r') as zip_ref:
            zip_ref.extractall(globalValues['sync_dir'])

        #verify signature
        check = Encclass.checkSignature(file, "./.signatures/"+file+".sig", server_pk)
        print("-----------Signature check-----------")
        print(check)
        if not check:
            print("Signature check failed")
            os.remove(globalValues['sync_dir']+"/"+file+".zip")
            os.remove(globalValues['sync_dir']+"/"+file+".key")
            os.remove(globalValues['sync_dir']+"/"+file+".sig")
            return
        
        #move keys to the keys directory
        shutil.move(globalValues['sync_dir']+"/"+file+".key", globalValues['keys_dir']+"/"+file+".key")

        #move the signature to the signatures directory
        shutil.move(globalValues['sync_dir']+"/"+file+".sig", globalValues['signature_dir']+"/"+file+".sig")

        #remove the zip file
        os.remove(globalValues['sync_dir']+"/"+file+".zip")


LoginForm()

# ========================================MENUBAR WIDGETS==================================
menubar = Menu(root)
root.config(menu=menubar)

# ========================================INITIALIZATION===================================
if __name__ == '__main__':
    global Encclass
    

    if not os.path.isfile('config.txt'): #first time running the program
        MakeConfigFile() #create config file with default values, and load them
        Encclass = EncryptionClass(globalValues)
        Register()
    else:
        LoadConfigFile() #loads global values from the config file
        Encclass = EncryptionClass(globalValues)
        client_pk = Encclass.client_pk
        client_sk = Encclass.client_sk

    
    #root.mainloop()
    auth = Authentication()
    if(auth != "1"):
        print("Authentication failed")
        exit()
    else:
        print("Authentication successful")

    #sk = loadPrivateKey()
    #pk = loadPublicKey()



    #encrypt dos ficheiros da diretoria
    sync_path = "sync"
    if not os.path.exists(sync_path):
        os.makedirs(sync_path)
    allFiles1 = set(os.listdir(sync_path))
    while(True):
        allFiles2 = set(os.listdir(sync_path))
        if allFiles1 != allFiles2: #changes in the directory
            if(len(allFiles1) > len(allFiles2)): #a file was deleted
                #for file in (allFiles1-allFiles2): os.remove("./.signatures/"+file+".sig")
                pass
            else: #a file was added
                for file in (allFiles2-allFiles1):
                    if(os.path.isfile(globalValues['keys_dir']+"/"+file+".key")): continue #file was received from server (already encrypted)
                    print("FILE:" + file)
                    Encclass.encrypt_file(file)
                    #pedir assinatura ao servidor
                    signature = sendFile(file)
                    #print(signature)
                    with open("./.signatures/"+file+".sig", "wb") as f: f.write(signature)
                    #verify signature
                    check = Encclass.checkSignature(file, "./.signatures/"+file+".sig")
                    if(not check): #invalid signature
                        print("Invalid signature")
                        os.remove("./.signatures/"+file+".sig")


            #ALERT THE SERVER
            
            allFiles1 = allFiles2


        #check for new files in server
        checkNewFilesInServer()

        time.sleep(10) #10 seconds
        #ask the server if there are any new files 