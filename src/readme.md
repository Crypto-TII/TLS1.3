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
	Private key= 0373AF7D060E0E80959254DC071A068FCBEDA5F0C1B6FFFC02C7EB56AE6B00CD
	Client Public key= 93CDD4247C90CBC1920E53C4333BE444C0F13E96A077D8D1EF485FE0F9D9D703
	Client to Server -> 16030100D6010000D2030348219C47B76BC8AD19E17DDB260CAA45108FBDFA75D982E04644AB1A88CDA0FF20557742FB051C8ADC0A421E53E1B1B862 (truncated)
	Client Hello sent
	Handshake Retry Request
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Server HelloRetryRequest= 020000540303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C20557742FB051C8ADC0A421E53E1B1B86268B4A1A6CC (truncated)
	Client to Server -> 16030300F7010000F3030364BA9C0C2B702B16F320C386D9E10F7619183314D2C09F36F97C8D24FBF2973720A0E658C6A5BB912768E0F844E81E4C3A (truncated)
	Server Hello= 020000970303266F6C36559FC37FD903D10FEABD3FC0BC44A7F409E387299ED5BFBB5FD68FE920A0E658C6A5BB912768E0F844E81E4C3AD7497548DB (truncated)

	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	Server Public Key= 04E9C3FADA28B71AD4520056538AB53683FE42F148EDA34F415DAAFE886D7D078AA632528CADA3E6B9F94D1540A376BBA7303538D5F4AB3CB3C953EC (truncated)

	Shared Secret= D627BCB77B718E77039A9160EF08E8AE2074731662108FE2ED98037B81A2144C
	Handshake Secret= D68D60D0FA44EC66340FD14FD547BA4A8A97A4787D9E510686187A2F89142B69
	Client handshake traffic secret= 55878ED5D82B19A7EC2FF113EEB3A661D58D819462755B8723A0671B4FFC6C8A
	Server handshake traffic secret= 3079EA79BC886DE53622D4FC9E5323E846B24C93D0968797A219F7E2ADF70009
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
	Checking RSA Signature on Cert
	RSA Signature/Verification succeeded
	Intermediate Certificate Chain sig is OK

	Public Key from root cert= DFAFE99750088357B4CC6265F69082ECC7D32C6B30CA5BECD9C37DC740C118148BE0E83376492AE33F214993AC4E0EAF3E48CB65EEFCD3210F65D22A (truncated)
	Checking RSA Signature on Cert
	RSA Signature/Verification succeeded
	Root Certificate sig is OK
	Certificate Chain is valid
	Transcript Hash= 545E351B536AEF9DB5B75480F157BC1858CF53FC22459EEC503C54A84A0E93B7
	Transcript Hash= 2791395F08115F2E7F9A7093230E77998E67543F4C74F274892AC4CCBD7DED69
	Signature Algorithm is RSA_PSS_RSAE_SHA256
	Server Certificate Signature= CDF23212CE6A2F4B57E4D39A976AB24923BDCB4D3C55EB979DF3A429A87A0EAD5D6C4069F8CD68963721278CB14EC557CF6B74F33F7FAFC0FBBD8046 (truncated)
	Server Cert Verification OK

	Server Data is verified
	Transcript Hash= C2678E4CB4F224CA32BCB899F76069D4525548FAAE174A16C4F252854FAD1248
	Client Verify Data= 6A0E1D2FE344A6521843771048AADB3F33B392F3B760D26B6FFF784602354CD1
	Client to Server -> 170303004456246163957822D2160BA17B4C8DFD2127E8AE27DD2D7CFF0AF7058AE61831B8023FAC03F9D64DAE0C1EDFC98B36B29F618035E4BE7215 (truncated)
	Client application traffic secret= AD5E2E5220AB17CF6DB8C55BA8ABE127C8F42A0242EB9557DA26AE3E9D81470F
	Server application traffic secret= 1A56C271773FCD1562FD25AF15BF36D5A1EE83CF0D8D74345D70292113602D8D
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
	Age obfuscator = 4643cf46
	Nonce = 00
	Ticket = D6F01670008D9251CA25A20CEBAE97896A74E45DCD9A5C6066C804D888552D5F
	max_early_data = 40960

	PSK= E4C4939F65AF0ED505EABEAAAB2EFCDB7146849977417A886ACB1F745B901030
	Binder Key= 8FC3DFE542C30CE77DF0117326E9319F39E3AB95D2042B7A920B5908FA67C28E
	Early Secret= A6B3057F2E8D20882C90F925C0DB08C44653C00DFBA3DE84C9A9302AC9A63587
	Private key= B2BE24A6B02F166305D4B3A5CC644BAFD31EADDDF28EA783EA5850FB046D230E
	Client Public key= 04DD8091A6A7134225F56F520450B3773A8B689F8E9090399D06C916DFFC4179F236F1ACA3F97B5794D6D5E7ADA7FBF38D29BD74E4A140DFA3CC803E (truncated)
	Ticket age= 44
	obfuscated age = 4643cf8a
	Client to Server -> 1603030105010001240303C20004D98AF9D915CE6807F3766E804D3F3EA72A6FDE3883C72786C21507CEEC2077898C8276DD669FF948C6C3980420F9 (truncated)
	Client Hello sent
	BND= D926B02A1853744E25B9766B6A9C9B8871F7BD8C016AE0A297726D3C55D755D5
	Sending Binders
	Client to Server -> 1603030023002120D926B02A1853744E25B9766B6A9C9B8871F7BD8C016AE0A297726D3C55D755D5
	Client Early Traffic Secret= 7777288E63EF514A64760A034FB66EC9EDA31B3B71E61C237042F9E06F9BE060
	Sending some early data
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org

	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	PSK Identity= 0
	Server Public Key= 047F31009A39B59326C358A74BCAF8EA605C8334F6FA57CC6759DB54B95A765C4937AC98D535BF2D78F76240D26A2276AB85A4EDBDC6BAA4E7E9E303 (truncated)

	serverHello= 0200009D0303266F6C37D061979B8739A772E73FFB51B3E0AE807A0BE0E1D3E4B95B3AE6BA802077898C8276DD669FF948C6C3980420F99E015F27A3 (truncated)
	Key Exchange Group is SECP256R1
	Shared Secret= DA685886BE538B5920DC86244772329A67E5C8902D8249FFC2F7BA4DEC5D56F2
	Handshake Secret= 2AA7664B9C7EA3FDD543678A494E0FDB252594D7A7829CCBC83999FAEF25C81A
	Client handshake traffic secret= C6E7BF467270A55DAE6267B48229230163D5B0CFF256D3D475F7A818EAC440C1
	Server handshake traffic secret= 25402669665624006539A1983212D820F9DDEF73D98C19C49343C18044DB8ACA
	Early Data Accepted
	Transcript Hash= 202D8A590A2FE45146070F011BE8CC61761A173981FCCFC4D3B848DA7FA7AC0B
	Send End of Early Data
	Client to Server -> 1703030020A57CD309194F004E006B0C9957F60F19F627231ABCD3D74DE75D44C25FC9A30E
	Transcript Hash= 58219792F8D0A4D5E26DF1CC3781E370FF51F213622567327A02DDBBE6443F97
	Server Data is verified
	Client Verify Data= 8334DEFCE2E6A7269D53CD74EF15E994B693C640D4F53EC60E2389280F7F8941
	Client to Server -> 1703030039337E0283EEB9944CD4B47D3ACA2A90FB17B902F3BAABC988CF95DA9CFD3F0879D3413DF15FABD9BEA534CA06C90BDA35095D73AEEE173A (truncated)
	Client application traffic secret= DD52CB02DEAF37188F6AA60AD086D680CCD000CAE13D4A009C1DC31D3F4D9C35
	Server application traffic secret= 1030EBC61767A293CC6ED9C2C63832D553CAD52F7C02B4FD6E43B4D5A9733FD9
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


