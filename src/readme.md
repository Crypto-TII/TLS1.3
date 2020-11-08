# Description

This C++ version is really just C plus namespaces. Namespaces are the only feature of C++ that is used. The Rust version will come later.

The starting point is this page https://tls13.ulfheim.net/

The initial idea is to implement two processes, server and client, which implement TLS1.3 over a local socket connection.

So far I have succeeded in reproducing the output down as far as the Application Keys calculation (which is close to the end of the protocol). 
The Crypto support (for hashing, HKDF, and X25519) for now  uses MIRACL Core https://github.com/miracl/core. 

This can be changed later, and other cipher primitive code added later on. For example Lightweight ciphers, post-quantum key exchanges etc.

So far this is just a very bare bones skeleton of an implementation, in no way ready for public scrutiny! So this repository is private for now.

I have it working here on a Windows machine, using WSL2 (Windows Subsystem for Linux).

To see the demo, first build the C++ version of MIRACL Core, selecting curves C25519 and NIST256.

Download the contents of this directory to a working directory, and copy into it core.a and the *.h files from the MIRACL Core build. Then

    g++ -O2 server.cpp tls_sockets.cpp tls_keys_calc.cpp tls_hash.cpp core.a -o server
    g++ -O2 client.cpp tls_sockets.cpp tls_keys_calc.cpp tls_hash.cpp core.a -o client

Run the server program in one window, and then the client program in another.

The (commented and slightly edited) output from the server app should be

	Client Hello Recieved
	Client Random= 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
	Session ID= e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
	Cipher Suite= 1301	// TLS_AES_128_GCM_SHA256
	Cipher Suite= 1302	// TLS_AES_256_GCM_SHA384 
	Cipher Suite= 1303	// TLS_CHACHA20_POLY1305_SHA256 
	Server Name= example.ulfheim.net
	Group = 1d		// X25519
	Group = 17		// NIST256 - SECP256R1
	Group = 18		// NIST384 - SECP384R1
	Signature alg = 403	// ECDSA_SECP256R1_SHA256
	Signature alg = 804	// RSA_PSS_RSAE_SHA256
	Signature alg = 401	// etc
	Signature alg = 503
	Signature alg = 805
	Signature alg = 501
	Signature alg = 806
	Signature alg = 601
	Signature alg = 201
	Key Share = 1d		//X25519
	Client Public Key= 358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
	Server Private key= 0x0faeadacabaaa9a8a7a6a5a4a3a2a1a02264c264c9ccec92872842f665cf9a02
	Server Public key= 0x9fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615

	Server Hello sent
	Hash= da75ce1139ac80dae4044da932350cf65c97ccc9e33f1e6f7d2d4b18b736ffd5
	Shared Secret= df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624
	Early Secret = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a

	Derived Secret = 6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba
	Handshake Secret= fb9fc80689b3a5d02c33243bf69a1b1b20705588a794304a6e7120155edf149a
	Client handshake traffic secret= ff0e5b965291c608c1e8cd267eefc0afcc5e98a2786373f0db47b04786d72aea
	Server handshake traffic secret= a2067265e7f0652a923d5d72ab0467c46132eeb968b6a32d311c805868548814
	Client handshake key= 7154f314e6be7dc008df2c832baa1d39
	Server handshake key= 844780a7acad9f980fa25c114e43402a
	Client handshake IV= 71abc2cae4c699d47c600268
	Server handshake IV= 4c042ddc120a38d1417fc815
	Hash= 22844b930e5e0a59a09d5ac35fc032fc91163b193874a265236e568077378d8b
	ciphered cert= da1ec2d7bda8ebf73edd5010fba8089fd426b0ea1ea4d88d074ffea8a9873af5f502261e34b1563343e9beb6132e7e836d65db6dcf00bc401935ae369c440d67af719ec03b984c4521b905d58ba2197c45c4f773bd9dd121b4d2d4e6adfffa27c2a81a99a8efe856c35ee08b71b3e441bbecaa65fe720815cab58db3efa8d1e5b71c58e8d1fdb6b21bfc66a9865f852c1b4b640e94bd908469e7151f9bbca3ce53224a27062ceb240a105bd3132dc18544477794c373bc0fb5a267885c857d4ccb4d31742b7a29624029fd05940de3f9f9b6e0a9a237672bc624ba2893a21709833c5276d413631bdde6ae7008c697a8ef428a79dbf6e8bbeb47c4e408ef656d9dc19b8b5d49bc091e2177357594c8acd41c101c7750cb11b5be6a194b8f877088c9828e3507dada17bb14bb2c738903c7aab40c545c46aa53823b120181a16ce92876288c4acd815b233d96bb572b162ec1b9d712f2c3966caac9cf174f3aedfec4d19ff9a87f8e21e8e1a9789b490ba05f1debd21732fb2e15a017c475c4fd00be042186dc29e68bb7ece192438f3b0c5ef8e4a53583a01943cf84bba5842173a6b3a7289566687c3018f764ab18103169919328713c3bd463d3398a1feb8e68e44cfe482f72847f46c80e6cc7f6ccf179f482c888594e76276653b48398a26c7c9e420cb6c1d3bc7646f33bb832bfba98489cadfbd55dd8b2c57687a47acba4ab390152d8fbb3f20327d824b284d288fb0152e49fc44678aed4d3f085b7c55de77bd45af812fc37944ad2454f99fbb34a583bf16b67659e6f216d34b1d79b1b4decc098a44207e1c5feeb6ce30acc2cf7e2b134490b442744772d184e59038aa517a97154181e4dfd94fe72a5a4ca2e7e22bce733d03e7d9319710befbc30d7826b728519ba74690e4f906587a0382895b90d82ed3e357faf8e59aca85fd2063ab592d83d245a919ea53c501b9accd2a1ed951f43c049ab9d25c7f1b70ae4f942edb1f311f7417833062245b429d4f013ae9019ff52044c97c73b8882cf03955c739f874a029637c0f0607100e3070f408d082aa7a2abf13e73bd1e252c228aba7a9c1f075bc439571b35932f5c912cb0b38da1c95e64fcf9bfec0b9b0dd8f042fdf05e5058299e96e4185074919d90b7b3b0a97e2242ca08cd99c9ecb12fc49adb2b257240cc387802f00e0e49952663ea278408709bce5b363c036093d7a05d440c9e7a7abb3d71ebb4d10bfc7781bcd66f79322c18262dfc2dccf3e5f1ea98bea3caae8a83706312764423a692ae0c1e2e23b016865ffb125b223857547ac7e2468433b5269843abbabbe9f6f438d7e387e3617a219f62540e7343e1bbf49355fb5a1938048439cba5cee819199b2b5c39fd351aa274536aadb682b578943f0ccf48e4ec7ddc938e2fd01acfaa1e7217f7b389285c0dfd31a1545ed3a85fac8eb9dab6ee826af90f9e1ee5d555dd1c05aec077f7c803cbc2f1cf98393f0f37838ffea372ff708886b05934e1a64512de144608864a88a5c3a173fdcfdf5725da916ed507e4caec8787befb91e3ec9b222fa09f374bd96881ac2ddd1f885d42ea584c
	authentication tag= e08b0e455a350ae54d76349aa68c71ae
	Derived Secret = de9f5c98db4261a46911f1349c1ba2c84dd84482249f8f2cb3a989e4e4a804e6
	Master Secret= 7f2882bb9b9a46265941653e9c2f19067118151e21d12e57a7b6aca1f8150c8d
	Client application traffic secret= b8822231c1d676ecca1c11fff6594280314d03a4e91cf1af7fe73f8f7be2c11b
	Server application traffic secret= 3fc35ea70693069a277956afa23b8f4543ce68ac595f2aace05cd7a1c92023d5
	Client application key= 49134b95328f279f0183860589ac6707
	Server application key= 0b6d22c8ff68097ea871c672073773bf
	Client application IV= bc4dd5f7b98acff85466261d
	Server application IV= 1b13dd9f8d8f17091d34b349
	Server Response sent

So here the client has confirmed to the server the AEAD cipher suites, the key exchange algorithms, and the certificate signing algorithms it supports.

The client app produces similar output, finishing withe same agreed keys. Everything that comes after this will be encrypted.

Note the use of OCT* functions from MIRACL Core. These provide a memory-safe way of processing octet strings, far superior to C++ char arrays.

