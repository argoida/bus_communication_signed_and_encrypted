from ascon.ascon import ascon_encrypt
from _thread import *
import random, socket

# Parameters for ASCON encryption
symmetric_key = b'ABCDEF1234567890'
nonce = b'6jhuih4weh2uqw09' 
ad = b'CAN_FD'                      #Associated data

# Creating session key from the symmetric key and a random session ID
session_id = random.getrandbits(128)
session_key = ascon_encrypt(symmetric_key, nonce, ad, str(session_id).encode())
session_key = int(session_key.hex()[:32],16).to_bytes(16, 'big')
open("session_key.txt",'wb').write(session_key)

# Initializing the CAN FD bus server
ServerSocket = socket.socket()
host = '127.0.0.1'
port = 20202
ServerSocket.bind((host, port))
print('Waiting for a connection...')
ServerSocket.listen(5)

# Receive function, used to receive messages from ECUs
def receive(Client):
    print(clients)
    while True:
        recv_data = Client.recv(4096)
        for client in clients:
            if client != Client:
                client.send(recv_data)

# Clients list to store cleint data
clients = []
while True:
    # Accept connections and add client to list
    Client, address = ServerSocket.accept()
    clients.append(Client)
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    # Start receiving threads
    if len(clients) == 3:
        for client in clients:
            start_new_thread(receive, (client,))
