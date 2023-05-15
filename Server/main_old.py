import socket
import threading

connected_clients = []

class Client:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.listen()

    #listen for upcoming messages
    def listen(self):
            self.conn.sendall(b"Hello, world")
            while True:
                data = self.conn.recv(1024)
                if not data: break
                # conn.sendall(data)
                print(data)

if __name__ == "__main__":
    while(True):
        print("Listening for clients")
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.bind(("127.0.0.1", 65432))
        new_socket.listen()
        conn, addr = new_socket.accept()  # wait for connection
        print("Connected to client: ", addr)
        #create a new thread for the client
        t = threading.Thread(target=Client, args=(conn, addr))
        t.start()




