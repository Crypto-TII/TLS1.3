# Description

UPDATE: The Crypto support functions are now all concentrated in the tls_sal_*.xpp files. This will make it easier to use alternate crypto providers.

This C++ version is really just C plus namespaces plus pass-by-reference. These the only features of C++ that are used. The Rust version will come later.
Documentation can be found in the doxygen generated file refman.pdf

First inside a working directory build the C++ version of MIRACL core (https://github.com/miracl/core), selecting support for C25519, NIST256, NIST384, RSA2048 and RSA4096.

This library does all the crypto, and can be regarded as a "placeholder" as we may in the future replace its functionality from other sources.
Make sure to always use the latest version of this library - as the requirements of this project unfold, some minor updates will be required.

Then copy the contents of this archive to the same directory, in particular client.cpp and tls*.*

Set the verbosity of the output in tls1_3.h to IO_DEBUG. 

Decide which crypto providers to use.

If using only the miracl library 

	cp tls_sal_m.xpp tls_sal.cpp

If using miracl+libsodium 

	cp tls_sal_ms.xpp tls_sal.cpp

If using miracl+tiicrypto 

	cp tls_sal_mt.xpp tls_sal.cpp

Build the tls library and the client app by 

	g++ -O2 -c tls*.cpp
	ar rc tls.a tls_protocol.o tls_keys_calc.o tls_sockets.o tls_cert_chain.o tls_client_recv.o tls_client_send.o tls_tickets.o tls_logger.o tls_cacerts.o tls_sal.o tls_octads.o tls_x509.o

If using miracl only	

	g++ -O2 client.cpp tls.a core.a -o client

If using miracl+libsodium  

	g++ -O2 client.cpp tls.a core.a -lsodium -o client

If using miracl+TIIcrypto 

	g++ -O2 client.cpp tls.a core.a libtiicrypto-v2.3.0.a -o client


Or by using CMake. If you follow this alternative, copy the header files into `vendor/miracl/includes`, and the `core.a` to `vendor/miracl/` 

Then execute the client process as for example

	./client swifttls.org

The output should look something like

	Hostname= swifttls.org
	Private key= 0C3FC34A2D8EA901FACDBE0FE0F0F4AD131C2883454BF24E97F475915520EB8C
	Client Public key= 443683ED24249F37960AB6AC8FBDC93109FDEB8319387244AA256A2CA03EC86D
	Client to Server -> 16030100D1010000CD03033166286BC15C82DA392A5A60C18BB39C82F2AD11D921AB83905C2E57159CF5D220D5D89E03B33D34870DC89936F495DDA0 (truncated)
	Client Hello sent
	Handshake Retry Request
	Cipher suite= 1301
	Server HelloRetryRequest= 020000540303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C20D5D89E03B33D34870DC89936F495DDA05DFAF25640 (truncated)
	Client to Server -> 16030300FA010000F6030320324B4040B508A94935E55168A49D0350A388A5217D9B5A015CADC191200B53204A3B5604C77DFD838307CF4E3004969E (truncated)
	Server Hello= 020000970303262A036458543CF385834B7F2C6A513CAC8D20DAD56E57A67D0C0757C5FC0289204A3B5604C77DFD838307CF4E3004969ED2272ECDAF (truncated)

	Parsing serverHello
	cipher suite= 1301
	Key exchange algorithm= 17
	Server Public Key= 04A4C0B7180710B9CEDD96D380D9269859667AB1E16EAF943A1BE1E3B9F4B5FAE3CA9208F28B2B294E4923E6FF8E53DC16F15198576A0326C41681FE (truncated)

	Shared Secret= BCE5D823527C6AD1FFF7DCF3526DDC0628A41EAF3A7163347004CA51F5FC2571
	Handshake Secret= C5C1C7C0C2761AD828ED9806EA536DF89D0622A18EFD11B57FD560DDCE839AEA
	Client handshake traffic secret= 8EC1C02FE7883DD52785E0F9F774C6E2A5070B540C15F6968255407C281C06BD
	Server handshake traffic secret= 7D09406EAB6434D63F9DDDADC28952962369A6B2718736D8E601778886004828
	Encrypted Extensions Processed
	Certificate Chain Length= 2458
	Parsing Server certificate
	Signature is 1FDE577C2557DACB149AE51372A2E91370C9D8BFC986F218614C5F2119332EA05B7792BC2E0E1411EC11B37C68B770155F61067861630F855B2857BF (truncated)
	RSA signature of length 2048
	Public key= D4292D40B3B245889F3041F336F38C0EEF644A2D762FBB9ACEC5CC3B52C013A83BD61160BBE47D0E04B6231FBC3DFFBAFA7287B19396E7ADC45436B7 (truncated)
	RSA public key of length 2048
	Issuer is  R3/Let's Encrypt/
	Subject is swifttls.org//
	Parsing Intermediate certificate
	Signature is D94CE0C9F584883731DBBB13E2B3FC8B6B62126C58B7497E3C02B7A81F2861EBCEE02E73EF49077A35841F1DAD68F0D8FE56812F6D7F58A66E353610 (truncated)
	RSA signature of length 2048
	Public key= BB021528CCF6A094D30F12EC8D5592C3F882F199A67A4288A75D26AAB52BB9C54CB1AF8E6BF975C8A3D70F4794145535578C9EA8A23919F5823C42A9 (truncated)
	RSA public key of length 2048
	Issuer is  DST Root CA X3/Digital Signature Trust Co./
	Subject is R3/Let's Encrypt/
	Checking RSA Signature on Cert
	RSA Signature/Verification succeeded
	Intermediate Certificate Chain sig is OK

	Public Key from root cert= DFAFE99750088357B4CC6265F69082ECC7D32C6B30CA5BECD9C37DC740C118148BE0E83376492AE33F214993AC4E0EAF3E48CB65EEFCD3210F65D22A (truncated)
	Checking RSA Signature on Cert
	RSA Signature/Verification succeeded
	Root Certificate sig is OK!!!!
	Certificate Chain is valid
	Transcript Hash= 29860499EFCC08ACD934C014008B8CD658E401F2208B23B13C5A34F1A8B3442C
	Transcript Hash= C20F01D9EB8A4BF0448F9FB996779DC0DB552883BBE1B5CC7C60E98BC926F5C7
	Signature Algorithm= 0804
	Server Certificate Signature= 68BB04F6FDB29FAE5F724CD3F8AF551E036D5FC3CA265CA52C4510807747285D5A27F1B14DF0F68258AB5399E5435F47C63665CB416F2447A2A8E177 (truncated)
	Server Cert Verification OK
	Server Data is verified
	Transcript Hash= 6BFDDB08AD63B6064858C10149619276256CDC2C121B6DCC645FE156571FF025
	Client Verify Data= 9462C267E5F53830819C11E0348517C184A0E23C5A93B0FD94050665B765E6F0
	Client to Server -> 1703030039B996F6635EB3961DD12DF2FA16B0E406AFA9E59100CCB8B9D112DC22403955FACC542D3EBD4811E574F1E3FC8FE3201DEF41D331C80E24 (truncated)
	Client application traffic secret= 30C3BE157E34324E87276FF4E47E2C48FB220F138F03ABB23A8DB8ADAAEA05FF
	Server application traffic secret= DD534A5AB1271F112DBF78BD1B2707FEC7A963209CB8DECA0DA7E581F654629C
	Full Handshake succeeded
	... after handshake resumption
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org

	Waiting for Server input
	Got a ticket
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Connection closed

	Attempting resumption

	Parsing Ticket
	life time in minutes = 60
	Age obfuscator = bcd22c8f
	Nonce = 00
	Ticket = DDA01C0CD305C8BEBD3DCA95A6A31A24242225A4532730B4818C4134431BB620
	max_early_data = 40960

	PSK= 53DA2F974F72C3DD67EE06162FBC062A71A2E2CD92465866AE1424E4C7369CFA
	Binder Key= 74541DF2514F4F0C732D57D27DAFF6E67361A891397259166D46D258C248AC1C
	Early Secret= 7ECF3F74EDA35BB3CD5A068E3329D45A78B3708094559CC6BE94AC76BA32255D
	Private key= D26D5D3BF4E9A38BB625D8EEA2138F729ED93DB6ED096BAD5A3D186021B32A55
	Client Public key= 040AFF235872593372C63B19656A4579C114208566063C9127C316363E9B913C78850C9708B694C27AE3BE22E0A26F55A79F8C74FE221A5016D02BDF (truncated)
	Ticket age= 34
	obfuscated age = bcd22cc3
	Client to Server -> 16030301200100013F030340C6FDFF02A29C0E5A7A676B4F89BDFA6B7B121CFC5E75D8A167CDC4D7EDFF15209966C3BF5A4F28C37A5146ACD51940C1 (truncated)
	Client Hello sent
	BND= 389E13BAB1C418C839195001DD79CA39788589E646784195D386400D88274A8B
	Sending Binders
	Client to Server -> 1603030023002120389E13BAB1C418C839195001DD79CA39788589E646784195D386400D88274A8B
	Client Early Traffic Secret= 643DA4E12823B2177DF5BF42A08DD5D65BBE7A3B5986A49A9E8FD25FD56EDC59
	Sending some early data
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org

	Parsing serverHello
	cipher suite= 1301
	Key exchange algorithm= 17
	PSK Identity= 0
	Server Public Key= 041E9B57D8ECE00AD04C98529848BFB7D930C430FB8363B4A3FE0B993739A6F2BFF27C7E763AEF2F50D8CAF1776513686271EB336DEFABD384BB8A05 (truncated)

	serverHello= 0200009D0303262A0365D7F54D94321729D8BB44FCDF662184BA49B46ECA40B0FE83CBB4A387209966C3BF5A4F28C37A5146ACD51940C179CC853A05 (truncated)
	Key Exchange= 23
	Shared Secret= 81344860A3B92AC5B58BA5BFE8CCA2B01A87FD9BAEAF9B650C7944850DD050AA
	Handshake Secret= A874C9BFDDCE8730DB8234B41DB90E381F3EB6F58B101DC7FC44D7F0D24770E4
	Client handshake traffic secret= BBB97E9F9CD935B098486E57A30DD32D3755B2D590CE777CEF012F2C20B8C8BA
	Server handshake traffic secret= 02E3135E14CE9DC0DB0096D4BB7492C1CA8D1526AD0DAD30410F97CACEF1B4B0
	Early Data Accepted
	Transcript Hash= 53D1DB99CD4E620007E203AF90E050789DEFA34AD892F335A588B123592DF965
	Send End of Early Data
	Client to Server -> 170303002455E05AB8AA341D54A2B7FD88819B016207A2928D996FEA8FD46254786565389464067F78
	Transcript Hash= BFCB925CD2B85CB6B6DE5F0B6BF9B84EA3BC1A29BA78DE8F41C50879792600D6
	Server Data is verified
	Client Verify Data= EF986A6F65D7A8EB4A785034C47732AB886E004B524D0ABCED1CC1A2B9621E84
	Client to Server -> 17030300438100EC4AC41ED92AB00C7812CA4B1B17EE6AD3EBFE3353CA12D63AC640E8AAA9521FD634721A0BF53F61BF7265F2CE38122B3D5E83F509 (truncated)
	Client application traffic secret= 7A5BC424336EEE03E3EC1F39FB0D18B60D6AF93AE660B9A60EEB86127F245587
	Server application traffic secret= DC0A47AD8128C3542EBB2BBB62D8099EC9712EA0E4278BA2EDED6935EA76770B
	Resumption Handshake succeeded
	Early data was accepted
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Connection closed 
	Try it out on your favourite websites. It will abort if TLS1.3 is not supported. 
	At this stage the tool is still quite fragile (only tested and debugged aginst a dozen websites or so!), and would be expected to often fail.
	In a small number of cases it will fail due to receiving a malformed certificate chain from the Server.

Also try

	./client tls13.1d.pw
	
Try it a few times - it randomly asks for a HelloRetryRequest and a Key Update, testing this code (but it does not allow resumption)

See list.txt for some websites that work OK.

## Client side Authentication

Another way to test less popular options is to set up a local openssl server. First generate a self-signed server certificate, then for example

	openssl s_server -tls1_3 -key key.pem -cert cert.pem -accept 4433 -www

acts as a normal Website, while

	openssl s_server -tls1_3 -verify 0 -key key.pem -cert cert.pem -accept 4433 -www

looks for client side certificate authentication - and the server makes a certificate request to the client. We can't control the openssl
debug output, but its better than nothing!

## Testing Pre-shared keys

Again we will use OpenSSL to mimic a TLS1.3 server

	openssl s_server -tls1_3 -cipher PSK-AES128-GCM-SHA256 -psk_identity 42 -psk 0102030405060708090a0b0c0d0e0f10 -nocert -accept 4433 -www

and connect via

	./client psk


### How to use it 

#### Localhost 4433

This is our own server, using TLSSwift (`localhost:4433`)

```bash
./client
```

#### Just Host

```bash
./client tls13.1d.pw
```

#### Host and port

```bash
./client localhost:1234
```

#### AF_UNIX Socket

```bash
./client af_unix /tmp/somesocket
```


### Building the client application on an Arduino board

1.	Create working directory directory with name NAME
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in the files config.py, client.cpp and tls*.* from this directory to the working directory
6.	Edit the file core.h to define CORE_ARDUINO
7.	Edit the file tls1_3.h to define POPULAR_ROOT_CERTS and TLS_ARDUINO
8.	Edit the file client.cpp to use your wifi SSID and password (near line 170)
9.	Run py config.py, and select options 2,3,8,40 and 42
10.	Drop the working directory into where the Arduino IDE expects it. 
11.	(In the IDE select File->Preferences and find the Sketchbook location - its the library directory off that.)
12.	Open the Arduino app, and look in File->Examples->NAME, and look for the example "client"
13.	Upload to the board and run it! Tools->Serial Monitor to see the output


