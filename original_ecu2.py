from ascon.ascon import ascon_encrypt, ascon_decrypt
from _thread import *
import socket, time

# ASCON encryption parameters
nonce = b'6jhuih4weh2uqw09'
ad = b'CAN_FD'
session_key = open("session_key.txt",'rb').read()

# ECU Identifier
identifier = b'02'

# Create ECU socket to connect to bus
ClientSocket = socket.socket()
host = '127.0.0.1'
port = 20202
ClientSocket.connect((host, port))

# Receive function to receive messages from ECUs
def receive():
    while True:
        # Start time
        start = time.time()
        # Receive the encrypted message
        Message_enc = ClientSocket.recv(4096)
        print("Received message.")
        print("Message: ", Message_enc.hex())
        # Decrypt the encrypted message
        Message = ascon_decrypt(session_key, nonce, ad, Message_enc)
        # If the identifier matches, print the message
        if Message[-2:] == identifier:
            print("Decrypted Message:", Message.decode())
        # If the identifier does not match, print this
        else:
            print("Message Authentication failed. Error frame has been sent!")
        # End time
        end = time.time()
        # Print execution time
        print(f"Execution time: {end-start} milliseconds")
        print("\n------------------------------------------------\n")

# Start receive thread
start_new_thread(receive, (()))
# Sending messages
while True:
    print("\n------------------------------------------------\n")
    # Get input 
    data = input("Message: ");
    # Encrypt message
    data_enc = ascon_encrypt(session_key, nonce, ad, data.encode())
    # Send message
    ClientSocket.send(data_enc)
    print("Data has been sent!")
    print("Identifier:", identifier.decode())
    print("Encrypted message:", data_enc.hex())