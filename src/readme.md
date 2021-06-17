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
	Client Hello sent
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Server HelloRetryRequest= 020000540303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C20557742FB051C8ADC0A421E53E1B1B86268B4A1A6CC (truncated)
	Client Hello re-sent
	Server Hello= 020000970303267B440A8FDD5AAFCE89BCCC40729F090B688743E160AB6F4F00CC9D8A077B7720A0E658C6A5BB912768E0F844E81E4C3AD7497548DB (truncated)
	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	Server Public Key= 0445F74493E090E5C6F9734E753181615E70F262773B2631ED648107E42D8D7C8CA276254781BA448C15873668E9FD57C505AA218BEB1F726AC3CCBD (truncated)

	Shared Secret= 720BAE2BC1B3E57CBBDB7FCBE67EAE9D53A418FC447FE5FAEE6CF03CD96F46AC
	Handshake Secret= D8B86E75D506C134176EDDFA7BA97895206FFB5628FF2D8BC303708E622F6CF9
	Client handshake traffic secret= 67E1C0882706014596274D5A34E338D84BCE68D96E4DEEFF29840D62F053569E
	Server handshake traffic secret= 83B7A088247EB6EFB78B1A02315DB241594B40C1F561572ED97D294FBEB6D1E5
	Warning - ALPN extension NOT acknowledged by server
	Server Name NOT acknowledged
	Max frag length request NOT acknowledged
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
	Transcript Hash (CH+SH+EE+CT) = 6598500DBD640A84AD24325C5D730BDE380365598A7960264597A5A02327879C
	Transcript Hash (CH+SH+EE+SCT+SCV) = 9AAF4F6B618D4F0F841F1757E4A6245CF05C2561B5E6BB84943BA337AD382CA3
	Server Certificate Signature= 1876F917CC0580BD9E2BFDBCB9D693FD3B286DBD9065B6EC29C04A860A0E61882AB436B57984A0F0501FA65020DE15BC87D1838B25EF7A144FCDADFC (truncated)
	Signature Algorithm is RSA_PSS_RSAE_SHA256
	Server Cert Verification OK

	Server Data is verified
	Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = 860D9C88942778F7F83D3DFAC9D2B347C3BABF9BCBA1A3EAB966E03806C61804
	Client Verify Data= CD0D6D333B0C52D179A0C3008B9E13F16CCD3DB7365FDFBA2D64AF0D2EC66640
	Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = 7F9ADB9127FAAF7C4698BEF3DB26227B88FD3D0844C529DFBBAA8C91312EEA4F
	Client application traffic secret= 28570358B3B6BD371F8E6D067733350EA4AD47890A70CC5DC5CE6BCCFD0A2ECF
	Server application traffic secret= 42F6933BFFB06207BAFFAA810CE7C84EA1AE04001A9F2373225DE1BADB07E8F0
	Full Handshake succeeded
	... after handshake resumption
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org


	Waiting for Server input
	Got a ticket
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Alert sent to Server - Close notify
	Connection closed

	Attempting resumption

	Parsing Ticket
	life time in minutes = 60
	Age obfuscator = 6a84f357
	Nonce = 00
	Ticket = B89AA26EED944AAB8C8B48293ACED3DF806DDA0A64796C865A2FDAF8CCD0E284
	max_early_data = 40960

	PSK= 74B636463CEBE875B5CADEBC1FB022810B6EA6984FA58E957795E9979D74BF29
	Binder Key= 60C2EC05E424A9033530B4A4644CE5BF893AADBEFC50B69962A1552CD2EAA47E
	Early Secret= 5D518801BE5D23F8A341C6ACDC134797594E2642735B552C38E9F0B075BE484D
	Private key= BE24A6B02F166305D4B3A5CC644BAFD31EADDDF28EA783EA5850FB046D230E98
	Client Public key= 04B593D22237E22583533A37898CDB74D86D500CAD7BCE59EF32F0166D977C3E76A23DF81121310093635CFE9C11BA8DDB54BCDE8BC7775AE552B29E (truncated)
	Ticket age= 38
	obfuscated age = 6a84f38f
	Client Hello sent
	BND= 4F4856443D2B30D07AC0639C29365FA9A3BB2B05E1DA9E991D7A8AC4A400888C
	Sending Binders
	Client Early Traffic Secret= 54D871D0579263A798C71620748FE34805C3F300C71B3598C9D4C089F2B59BBF
	Sending some early data
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org


	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	PSK Identity= 0
	Server Public Key= 042E45D04810BC6A16EDE859EE44284CAD0C46FC63D9802E628F4D2AFFE55092CFEA64B91B33A3EC49ABC3B25055E18B8A40C4FC0CB62978E4EC52B3 (truncated)

	serverHello= 0200009D0303267B440B183D03A4C84BCD0219A0E2990DBCA4723510F88F3FD2870CA369900D20898C8276DD669FF948C6C3980420F99E015F27A3FC (truncated)
	Shared Secret= C9C6823FE64A2A0E28525C59654ACEEEF42C59E2B2AD6216703A7B747C8C1D31
	Handshake Secret= E961F5E140CD939D2CF18E1BC7AF2995D6D60CF495CA4EA7D86B92D86FE4F046
	Client handshake traffic secret= FBEA2AE7DC1A3EB3FF23AE969C8EED24EE802DE467AB9B72F9CED1201AB6A9C2
	Server handshake traffic secret= E2E5BFA257DD140CA74232DB5048C643E40239C07929D0AC34A54316A47605C8
	Early Data Accepted
	Warning - ALPN extension NOT acknowledged by server
	Server Name NOT acknowledged
	Max frag length request NOT acknowledged
	Transcript Hash (CH+SH+EE) = 0C3AE9A9DE38AC962674A532D90F3623774DD2E7D3C2A4704429060206DD29DF
	Send End of Early Data
	Transcript Hash (CH+SH+EE+SF+ED) = 1E536FCCA58F32F7061A38748577ECA163D6BA5455CBDAD923E69FF39E26AA11
	Server Data is verified
	Client Verify Data= 51A23C4E4EA8F3D7600C3C406647B3A4F13D6398A829455AEBFB0A3F867D04E7
	Client application traffic secret= ACD82D6A9F00258A012191DA0CD976D218C96DFF67D7FA5D31E69A099B32A333
	Server application traffic secret= B427AC41917E466E85049DBCEA36B98098F748D224D743D32FDD3E05602327B4
	Resumption Handshake succeeded
	Early data was accepted
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Alert sent to Server - Close notify
	Connection closed
	
Try it out on your favourite websites. It will abort if TLS1.3 is not supported. 
At this stage the tool is still somewhat fragile, and would be expected to sometimes fail.
In a small number of cases it will fail due to receiving a malformed certificate chain from the Server. It is not forgiving of badly 
formed certificate chains, and makes no attempt to fix them.

Also try

	./client tls13.1d.pw
	
Try it a few times - it randomly asks for a HelloRetryRequest and a Key Update, testing this code (but it does not allow resumption)

See list.txt for some websites that work OK and test different functionality.

## Client side Authentication

A self-signed client certificate and private key can be generated by

	openssl req -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name secp384r1) -keyout mykey.pem -out mycert.pem

A way to test less popular options is to set up a local openssl server. First generate a self-signed server certificate using something like

	openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

then for example

	openssl s_server -tls1_3 -key key.pem -cert cert.pem -accept 4433 -www

acts as a normal Website, while

	openssl s_server -tls1_3 -verify 0 -key key.pem -cert cert.pem -accept 4433 -www

looks for client side certificate authentication - and the server makes a Certificate Request to the client. We can't control the openssl
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


### Building the client application on an Arduino board (like ESP32)

1.	Create working directory directory with name NAME
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in the files config.py, client.cpp and tls*.* from this directory to the working directory
6.	Edit the file core.h to define CORE_ARDUINO
7.	Edit the file tls1_3.h to define POPULAR_ROOT_CERTS and TLS_ARDUINO
8.	Edit the file client.cpp to use your wifi SSID and password (near line 170)
9.	Run py config.py, and select options 2,3,8,41 and 43
10.	Drop the working directory into where the Arduino IDE expects it. 
11.	(In the IDE select File->Preferences and find the Sketchbook location - its the library directory off that.)
12.	Open the Arduino app, and look in File->Examples->NAME, and look for the example "client"
13.	Upload to the board and run it! Tools->Serial Monitor to see the output

