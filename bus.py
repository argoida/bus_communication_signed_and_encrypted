import sys
from socket import *
import select
import signal

# Initializing the CAN FD bus server
host = '127.0.0.1'
port = 20202
#max_to_read = 64
max_to_read = 2048
sleep_in_select = 1
clients_sockets = []
msg_queue = []


def signal_handler(sig, frame):
    sys.exit(0)


def open_socket_to_listen():
    try:
        ADDR = (host, port)
        serversock = socket(AF_INET, SOCK_STREAM)
        serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serversock.bind(ADDR)
        serversock.listen(0)
        serversock.settimeout(1)  # no block
    except Exception as inst:
        print(f"Error trying to open socket to wait for connectiosn. Host {host}:{port}")
        sys.exit(2)
    return serversock


def prepare_select(serversock):
    test_to_read, test_to_write, test_exception = [], [], []
    test_to_read.append(serversock)
    test_exception.append(serversock)
    for c in clients_sockets:
        test_to_read.append(c)
        test_exception.append(c)
        if msg_queue:
            test_to_write.append(c)
    return test_to_read, test_to_write, test_exception


def main_loop(serversock):
    while True:
        test_to_read, test_to_write, test_exception = prepare_select(serversock)
        readable, writable, exceptional = select.select(test_to_read, test_to_write, test_exception, sleep_in_select)
        if readable:
            for cs in readable:
                if serversock == cs:
                    clientsock, addr = serversock.accept()
                    print(f"Accepted connected from: {addr}   local {clientsock.getsockname()}")
                    clients_sockets.append(clientsock)
                else:
                    rcvdata = None
                    try:
                        rcvdata = cs.recv(max_to_read)
                    except Exception as e:
                        pass
                    if rcvdata:
                        msg = (cs, rcvdata)
                        msg_queue.append(msg)
                    else:
                        cs.close()
                        clients_sockets.remove(cs)
        if writable:
            while msg_queue:
                msg = msg_queue.pop(0)
                for cs in clients_sockets:
                    if cs != msg[0]:
                        try:
                            cs.send(msg[1])
                        except Exception as e:
                            print(f"Error sending data to socket {cs} {e}")
                            cs.close()
                            clients_sockets.remove(cs)
        if exceptional:
            for cs in exceptional:
                print(f"Exception on socket {cs}. Closing.")
                cs.close()
                clients_sockets.remove(cs)


signal.signal(signal.SIGINT, signal_handler)
main_loop(open_socket_to_listen())
