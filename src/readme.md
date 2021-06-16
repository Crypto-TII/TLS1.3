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

The test TLS client app tries to connect to a Web site, drops the connections, and then attempts a resumption. Execute the client process as for example

	./client swifttls.org

The output should look something like

	Hostname= swifttls.org
	Private key= 0373AF7D060E0E80959254DC071A068FCBEDA5F0C1B6FFFC02C7EB56AE6B00CD
	Client Public key= 93CDD4247C90CBC1920E53C4333BE444C0F13E96A077D8D1EF485FE0F9D9D703
	Client to Server -> 16030100E5010000E1030348219C47B76BC8AD19E17DDB260CAA45108FBDFA75D982E04644AB1A88CDA0FF20557742FB051C8ADC0A421E53E1B1B862 (truncated)
	Client Hello sent
	Handshake Retry Request
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Server HelloRetryRequest= 020000540303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C20557742FB051C8ADC0A421E53E1B1B86268B4A1A6CC (truncated)
	Client to Server -> 160303010601000102030364BA9C0C2B702B16F320C386D9E10F7619183314D2C09F36F97C8D24FBF2973720A0E658C6A5BB912768E0F844E81E4C3A (truncated)
	Server Hello= 020000970303267374C6F6ABC13209CF0317E0D4C54C0B53769668B0471C9F0C99E26292657720A0E658C6A5BB912768E0F844E81E4C3AD7497548DB (truncated)
	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	Server Public Key= 04DBDAC433E340CCE52AF4AEE4D92C5D02A1CA3A0AC0A4A936000CD07E574D71120ED94E76B00ADAD0527CA1C556A1769BF0D99F8398A8B1D4FDB487 (truncated)

	Shared Secret= D2F2C6A7168BD9148F4F9EF8AED6A98167C6E4FBB622DD33A3BE74145A1B6F07
	Handshake Secret= 2437B991C1DC51AAA35ED8A49B7FA01F110C59A54B379A1E37A080C04EBEF9D4
	Client handshake traffic secret= B183E2BD906E2CE4AC4B50CF36A616637D30BFE0288006E25AC456C11940ABF5
	Server handshake traffic secret= ABEC73EF21349C6139D033565330EE8CFBF5602DF3E7D2FEC1509F8B4DE19728
	Warning - ALPN extension NOT acknowledged by server
	Server Name NOT Acknowledged
	Encrypted Extensions Processed
	Certificate Chain Length= 2458
	Parsing Server certificate
	Signature is 0A5C155DB6DD9F7F6ABE005D351D6E3FF9DEBA799F7479BD33E1C784B63CB4CA695A76815C9B666C24B6E989EE85009A6E35D68B9E190ED6444248E4 (truncated)
	RSA signature of length 2048
	Public key= E2AB76AE1A676E3268E39BB9B8AE9CA19DD8BC0BFED0A4275E13C191D716794B48F47766A6B6AD17F19764F48D459E8271721BCAE2D0D2AB34706381 (truncated)
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
	Signature  = 0A5C155DB6DD9F7F6ABE005D351D6E3FF9DEBA799F7479BD33E1C784B63CB4CA695A76815C9B666C24B6E989EE85009A6E35D68B9E190ED6444248E4 (truncated)
	Public key = BB021528CCF6A094D30F12EC8D5592C3F882F199A67A4288A75D26AAB52BB9C54CB1AF8E6BF975C8A3D70F4794145535578C9EA8A23919F5823C42A9 (truncated)
	Checking Signature on Cert
	Signature Algorithm is RSA_PKCS1_SHA256
	Cert Signature Verification succeeded
	Intermediate Certificate Chain sig is OK

	Public Key from root cert= DFAFE99750088357B4CC6265F69082ECC7D32C6B30CA5BECD9C37DC740C118148BE0E83376492AE33F214993AC4E0EAF3E48CB65EEFCD3210F65D22A (truncated)
	Signature  = D94CE0C9F584883731DBBB13E2B3FC8B6B62126C58B7497E3C02B7A81F2861EBCEE02E73EF49077A35841F1DAD68F0D8FE56812F6D7F58A66E353610 (truncated)
	Public key = DFAFE99750088357B4CC6265F69082ECC7D32C6B30CA5BECD9C37DC740C118148BE0E83376492AE33F214993AC4E0EAF3E48CB65EEFCD3210F65D22A (truncated)
	Checking Signature on Cert
	Signature Algorithm is RSA_PKCS1_SHA256
	Cert Signature Verification succeeded
	Root Certificate sig is OK
	Certificate Chain is valid
	Transcript Hash= 009914583333AEBD14E04F9960BC9E4F1DA264B283D13AE5A830D816B9E0FE4E
	Transcript Hash= 20FE6702F64323FC8D2F6FA56E4F02B3EC89EF1063278C378DE887E64A52023B
	Server Certificate Signature= 8FA8AAE331DEB9EAEC746CA31ABD293C4BABBFE70745A9F491AC6E96B96FF3DB3942BBA990052B506176ABC88A70DB0E5126D425101ED21C7E9753B9 (truncated)
	Signature Algorithm is RSA_PSS_RSAE_SHA256
	Server Cert Verification OK

	Server Data is verified
	Transcript Hash= 23542FEAA48D469273FCF0F73CF3D62C026CCFC9B5AF03A5DC3E4F17425A45E6
	Client Verify Data= 356518A7CE91F351D4E51E2CCF7BAE6F45DDE18710F11F5B82D3D37D278D7A29
	Client to Server -> 17030300449A2F8BA35986761B0C1C5ADAEE9C78FC2D5DCF96FD8844BC84665CED01AB732D017C7F931362D31EAA54E49B9D4602B11167D08CAB7E55 (truncated)
	Client application traffic secret= 75FF1BDEE81A66C4DF287CAE3C7CF64D2A66A664FC423DC4392D03BBC27CE707
	Server application traffic secret= 2E437FA0058054C34953568BD48F3CD869CB750894ADDE6407A9105DF8B87E83
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
	Age obfuscator = e01e88b5
	Nonce = 00
	Ticket = B5C413F5D46D4FAB1EA31CED3F342B9887425F5E4E33C4E9F71CA410DD1C0B93
	max_early_data = 40960

	PSK= B7AE97009D6FB27BE6FE91AA46B40FDA05B109F12911BF878CCF71AB79EE93B3
	Binder Key= 5E1361389B77C42A9E8C1D9FC0FC01E5FB8B6CBC7C963679390BA06858E64941
	Early Secret= DF69A43C7507B123F59ED427926A33D6A559167AC0B6201E1924B36C519081A1
	Private key= B2BE24A6B02F166305D4B3A5CC644BAFD31EADDDF28EA783EA5850FB046D230E
	Client Public key= 04DD8091A6A7134225F56F520450B3773A8B689F8E9090399D06C916DFFC4179F236F1ACA3F97B5794D6D5E7ADA7FBF38D29BD74E4A140DFA3CC803E (truncated)
	Ticket age= 34
	obfuscated age = e01e88e9
	Client to Server -> 1603030114010001330303C20004D98AF9D915CE6807F3766E804D3F3EA72A6FDE3883C72786C21507CEEC2077898C8276DD669FF948C6C3980420F9 (truncated)
	Client Hello sent
	BND= 62311EA9BBD18AA7929D1F103F37BB49756E8FA97F4F2F918E27656D005BCCA3
	Sending Binders
	Client to Server -> 160303002300212062311EA9BBD18AA7929D1F103F37BB49756E8FA97F4F2F918E27656D005BCCA3
	Client Early Traffic Secret= 096D42B97067974660668C971BA2E3890A7BCDD10DEC6721354CB8D4FECD2648
	Sending some early data
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org


	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	PSK Identity= 0
	Server Public Key= 045AD14B24FBEB2A56E4D9FF050A6372ECB329A9907FE7739C56CE6BEF09FDAD51623E23B3A2DFA739274D4FDF1FBE26C35420BA78DBF2DD909B36CF (truncated)

	serverHello= 0200009D0303267374C78BD760AA7A7C97B9B0C2513805B09653E45A3CDB76E1EC53FDF7E6DD2077898C8276DD669FF948C6C3980420F99E015F27A3 (truncated)
	Shared Secret= 724F76AAA8157BBC6FC072B70BF26054F62EE1E831E4FBBC02765EDD087B6011
	Handshake Secret= AD049FAE721797DD0078436FD92139172D2C5570C52CF991D3EF795D472B701E
	Client handshake traffic secret= 243DDFF0AD49EBA19D7FD2EECE3718B3B8FDD172CF833F705EABFACC6545A38A
	Server handshake traffic secret= 829E8F8A1EA13C7C7F603E4DD61C728D7B99DC21AD91F2FA55B7A2C6661A9268
	Early Data Accepted
	Warning - ALPN extension NOT acknowledged by server
	Server Name NOT Acknowledged
	Transcript Hash= FA775FF04D6FEE07DD9935D2A4BCB60B717ED0C6CB1E34CC40306570A45C2BA4
	Send End of Early Data
	Client to Server -> 170303002044B3C7F3A5964D67212A693DE6E04951DF5F0CB0EAA7A59937B62B08B1B6C8B0
	Transcript Hash= 4B287F921879798321E8DC1886FD8C5898BE3DA7E2DE18E13353100E03671EB3
	Server Data is verified
	Client Verify Data= 71A0D71AA782C671D34DD261CD6E49B6C40742308DF688A7637688EC00782503
	Client to Server -> 170303003908D00F304E8B7113C41BA532F4BE7D139F8681FEFE9A9C814AAE7B3C8986B5406DE4E02FA80ED582D1F2C181E87A0F4299193B72A860A0 (truncated)
	Client application traffic secret= C6A112E7C0873BE7C80AB08E5B0CFCCB9B8DFEB3309ED185A34B75A20C0FE9F0
	Server application traffic secret= 86488942A19801E5A010E75BB935DDB06C9DCE5CDA4B704D5F8943EE0C28BB58
	Resumption Handshake succeeded
	Early data was accepted
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Connection closed
	
Try it out on your favourite websites. It will abort if TLS1.3 is not supported. 
At this stage the tool is still quite fragile (only tested and debugged aginst a dozen websites or so!), and would be expected to often fail.
In a small number of cases it will fail due to receiving a malformed certificate chain from the Server. It is not forgiving of bad certificate 
chains. and makes no attempt to fix them.

Also try

	./client tls13.1d.pw
	
Try it a few times - it randomly asks for a HelloRetryRequest and a Key Update, testing this code (but it does not allow resumption)

See list.txt for some websites that work OK and test different functionality

## Client side Authentication

A client side self-signed certificate and private key can be generated by

	openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name secp384r1) -keyout mykey.pem -out mycert.pem

Another way to test less popular options is to set up a local openssl server. First generate a self-signed server certificate using something like

	openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

then for example

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


