import os
import socket
import threading
import pickle


def firstConfiguration(config_file):
    config = {}
    while (True):
        sync_folder = input("Enter the folder to sync: ")
        # check if folder is empty
        if (os.listdir(sync_folder)):
            print("Folder is not empty")
            # TO-DO: encrypt files
            continue
        config['SYNC FOLDER'] = sync_folder
        break

    # generate and save RSA keys
    # TO-DO

    # write configurations to file
    with open("config.txt", "wb") as f:
        pickle.dump(config, f)
    return config


def sendMsgServer(csocket, msg):
    csocket.sendall(b"Hello, world")


# listen for upcoming messages (commands) from the server
def listen(csocket):
    while True:
        data = csocket.recv(1024)
        if not data: break
        # conn.sendall(data)
        print(data)



if __name__ == "__main__":
    # get the configurations (check if is the first time executing the program)
    config_file = "config.txt"
    try:
        with open(config_file, "rb") as f:
            print("Config file found")
            config = pickle.load(f)
    except:
        print("Config file not found")
        config = firstConfiguration(config_file)

    # check if exists a file not encrypted nor synced
    #TO-DO

    # connect to server
    HOST = "127.0.0.1"  # The server's hostname or IP address
    PORT = 65432  # The port used by the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while (True):
        try:
            s.connect((HOST, PORT))
            break
        except:
            print("waiting for server")
            continue

    print("Connected to server")
    listen(s)










