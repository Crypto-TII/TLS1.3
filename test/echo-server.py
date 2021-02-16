#!/usr/bin/env python3

import socket

import sys
import os

server_address = '/tmp/somesocket'

# Make sure the socket does not already exist
try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise


with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.bind(server_address)
    while True:
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(bytes([65,17,34,34,12,12,2,65]))