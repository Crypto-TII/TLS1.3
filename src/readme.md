# Description

This C++ version is really just C plus namespaces. Namespaces are the only feature of C++ that is used. The Rust version will come later.

The starting point is this page https://tls13.ulfheim.net/

The initial idea is to implement two processes, server and client, which implement TLS1.3 over a local socket connection.

So far I have succeeded in reproducing the output down as far as the Handshake Keys calculation. The Crypto support (for hashing, HKDF, and X25519) for now uses MIRACL Core https://github.com/miracl/core. 

This can be changed later, and other cipher primitive code added later on. For example Lightweight ciphers, post-quantum key exchanges etc.

So far this is just a very bare bones skeleton of an implementation, in no way ready for public scrutiny! So this repository is private for now.

I have it working here on a Windows machine, using WSL2 (Windows Subsystem for Linux).

To see the demo, first build the C++ version of MIRACL Core, selecting curves C25519 and NIST256.

Download the contents of this directory to a working directory, and copy into it core.a and the *.h files from the MIRACL Core build. Then

    g++ -O2 server.cpp core.a -o server
    g++ -O2 client.cpp core.a -o client

Run the server program in one window, and then the client program in another.

The (commented and slightlt edited) output from the server app should be

    Client Hello received	
    Client Random= 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    Session ID= e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff
    Cipher Suite= 1301   // TLS_AES_128_GCM_SHA256
    Cipher Suite= 1302   // TLS_AES_256_GCM_SHA384 0x1302
    Cipher Suite= 1303   // TLS_CHACHA20_POLY1305_SHA256 0x1303
    Server Name= example.ulfheim.net
    Group = 1d           // X25519
    Group = 17           // NIST256 - SECP256R1
    Group = 18           // NIST384 - SECP384R1
    Signature alg = 403  // ECDSA_SECP256R1_SHA256
    Signature alg = 804  // RSA_PSS_RSAE_SHA256
    Signature alg = 401  // etc
    Signature alg = 503
    Signature alg = 805
    Signature alg = 501
    Signature alg = 806
    Signature alg = 601
    Signature alg = 201
    Key Share = 1d       // Server chooses X25519
    Client Public Key= 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54

    Server Private key= 0x0f ae ad ac ab aa a9 a8 a7 a6 a5 a4 a3 a2 a1 a0 22 64 c2 64 c9 cc ec 92 87 28 42 f6 65 cf 9a 02
    Server Public key=  0x9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15

    Server Hello= 16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 01 00 00 2e 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15 00 2b 00 02 03 04

    Server Hello sent
    Transcript Hash= da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5
    Shared Secret= df 4a 29 1b aa 1e b7 cf a6 93 4b 29 b4 74 ba ad 26 97 e2 9f 1f 92 0d cc 77 c8 a0 a0 88 44 76 24
    Early Secret = 33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a
    Derived Secret = 6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba
    Handshake Secret= fb 9f c8 06 89 b3 a5 d0 2c 33 24 3b f6 9a 1b 1b 20 70 55 88 a7 94 30 4a 6e 71 20 15 5e df 14 9a
    Client handshake traffic secret= ff 0e 5b 96 52 91 c6 08 c1 e8 cd 26 7e ef c0 af cc 5e 98 a2 78 63 73 f0 db 47 b0 47 86 d7 2a ea
    Server handshake traffic secret= a2 06 72 65 e7 f0 65 2a 92 3d 5d 72 ab 04 67 c4 61 32 ee b9 68 b6 a3 2d 31 1c 80 58 68 54 88 14
    Client handshake key= 71 54 f3 14 e6 be 7d c0 08 df 2c 83 2b aa 1d 39
    Server handshake key= 84 47 80 a7 ac ad 9f 98 0f a2 5c 11 4e 43 40 2a
    Client handshake IV= 71 ab c2 ca e4 c6 99 d4 7c 60 02 68
    Server handshake IV= 4c 04 2d dc 12 0a 38 d1 41 7f c8 15

So here the client has confirmed to the server the AEAD cipher suites, the key exchange algorithms, and the certificate signing algorithms it supports.

The client app produces similar output, finishing withe same agreed keys. Everything that comes after this will be encrypted.

Note the use of OCT* functions from MIRACL Core. These provide a memory-safe way of processing octet strings, far superior to C++ char arrays.

