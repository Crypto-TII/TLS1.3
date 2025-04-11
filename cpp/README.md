# TIIGER TLS C++

This C++ project implements a TLS1.3 client. There is also a Rust version available from this site. This C++ version is really just C plus namespaces plus pass-by-reference. These are the only features 
of C++ that are used. Documentation can be found in the doxygen generated file doc/refman.pdf

<img src="https://img.shields.io/badge/language-c++-blue.svg"/>
<img src="https://img.shields.io/badge/platform-mac | linux | win | arduino-lightgrey.svg?style=flat"/>

# Building

The TLS library is designed to support crypto agility by allowing a mix of cryptographic providers. This functionality is provided by the SAL (Security Abstraction Layer). 
Below are two examples to choose from. The SAL API documentation is provided in sal/sal.pdf, and guided by this it should be possible to create your own SAL.
To build the client on an IoT node like the Arduino RP2040, see the readme file in the src/arduino directory.

Private keys, server/client certificate chains, and CA root stores are all fixed in the code.

Ideally keys, chains and key stores should be kept in external files, but in an IoT setting there may not be a file system. 
In this C++ code the client private key and certificate (only required for client-side authentication) are stored in the source code file *tls_client_cert.cpp*. The root certificate store is 
stored in the file *tls_cacert.cpp*.
When using secure hardware, the client private key may not be embedded in the source code, rather it exists in secure on-board memory.

The installation process requires the *cmake* utility to be installed. Copy all files and subdirectories from this directory to a working directory.
If necessary make configuration changes in *include/tls1_3.h*, in particular to select the CRYPTO\_SETTING. For now leave it unchanged as TYPICAL


## Miracl

This build gets all of it cryptography from the MIRACL core library https://github.com/miracl/core/cpp

	bash ./scripts/build.sh -1

## Miracl + LibSodium

To use a SAL which includes some functionality from the well known sodium crypto library https://libsodium.gitbook.io/doc/, install sodium, then

	bash ./scripts/build.sh -2

## Miracl + TLSECC

For a SAL with much faster elliptic curve cryptography, use the TLSECC library https://github.com/mcarrickscott/TLSECC. Recommended.

	bash ./scripts/build.sh -3

# Try it out

After the build complete successfully, the example executable *client* and the TiigerTLS library *libtiitls.a* are generated in the build directory.

The client application can be modified and rebuilt from this directory at any time unless changes are made that impact the SAL. For example if using the Miracl+TLSECC SAL, then

	g++ -O2 client.cpp tls*.cpp libtiitls.a core.a tlsecc.a -o client

For example you can edit the file *tls1_3.h* and set VERBOSITY to IO\_DEBUG, and re-compile as above.

To see the Security Abstraction Layer (SAL) capabilities, navigate to the build directory
	
	./client -s

To connect to a Website

	./client swifttls.org

The output should (if VERBOSITY has been set to IO\_DEBUG in *tls1_3.h*) look something like this

	Hostname= swifttls.org
	Private key= 0373AF7D060E0E80959254DC071A068FCBEDA5F0C1B6FFFC02C7EB56AE6B00CD
	Client Public key= 93CDD4247C90CBC1920E53C4333BE444C0F13E96A077D8D1EF485FE0F9D9D703
	Client Hello sent
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Server HelloRetryRequest= 020000540303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C20557742FB051C8ADC0A421E53E1B1B86268B4A1A6CC (truncated)
	Client Hello re-sent
	Server Hello= 020000970303268C697006F0AC66287680A88C6DB34C2804CD9884B2B0BD087A0F3DE2495F5120A0E658C6A5BB912768E0F844E81E4C3AD7497548DB (truncated)
	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	Server Public Key= 04F87B11F808F92B9D4DAE8AE83389257F04B3697181F3CD1479B7214E7D76B108B650A57494D15C5F673EDB05D1C6E05C49B161B7056173AF454257 (truncated)

	Shared Secret= 99A5F3B6F8BE0938AB6D74A99E8FD42DEFD71F25445BD703F0D429DA6CC4AA12
	Handshake Secret= 093388E25C3F8468DF3A0544683036CBACF5157874CE995C080807559834CBCA
	Client handshake traffic secret= 5B383ED973C7324E267B16A1A7507C380846FFB5397B41E3199C305C23A2C430
	Server handshake traffic secret= 71A23E7184F1AA8F228504D3FA735EC8E70FFEC54E0922D553A64800A32C2853
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
	Transcript Hash (CH+SH+EE+CT) = 7CECF69D794C20FB7551BA5C4B986E1F501011328225CDD740A8EB54B728E31B
	Transcript Hash (CH+SH+EE+SCT+SCV) = 8EC0EE587717BAEB401992622E3F31CBE151CC6C489104E68B5A83E96284E1E7
	Server Certificate Signature= B5B74CF6026CF16FA866BA7E7562C53F67A74949FF040319B0BD2149CF4EF97CAD482463F1746D202B1EE0FF0137A737FAD757FB606F809A949F95DC (truncated)
	Signature Algorithm is RSA_PSS_RSAE_SHA256
	Server Cert Verification OK

	Server Data is verified
	Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = 299C505CBD66E8CCCF1934AC5398EFAB7DCF239D9A9C95CF0A5384B5902E6A12
	Client Verify Data= 9D20AD7C24238C5B77B72D40EC355C41C5859B6851639EA9920986EDF50DF032
	Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = 50AC5EA2A163FD5A3CE92D7D98E8CB56D763514148A30213784612F9B87C991B
	Client application traffic secret= 7DE3D4B470FBCA72FEECBA1A1B938F4AF85F0E4D84C8E06E4218A92DF3EE67CF
	Server application traffic secret= 11FFA6345BE788BBF8C1948E4F499D852A07A77B74C74F560BC9E399AB41ABC8
	Full Handshake concluded
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

To attempt a fast resumption, based on a resumption ticket (generated and stored in a file cookie.txt), connect again

	./client swifttls.org

The output should look something like

	Attempting resumption
	Hostname= swifttls.org

	Parsing Ticket
	Ticket = 6CE7CD561F03F6E3CDD9A0DD4A7F37181861F51A17E8FF6930AAA02C6C5DAFD9
	life time in minutes = 3600
	Pre-Shared Key = 41301AAD7DAADCF43D700CD71E1198DD2C8DFF5C61B91BEA35116B96762C8B7E
	max_early_data = 40960

	PSK= 41301AAD7DAADCF43D700CD71E1198DD2C8DFF5C61B91BEA35116B96762C8B7E
	Binder Key= 3CC796B38A7FEB226D9B0CD6B6BB4994253298DDF9FF43060C5C30834D75EE79
	Early Secret= 610B9D95E512F6E199046C93E600D5CE10BB98517F9A81096E653C13B2D0F17D
	Private key= 7373AF7D060E0E80959254DC071A06905E067B07367C49D86B48A10F3923CC49
	Client Public key= 04EA04CDA74C1A1942BB8C56C0BD8AE1A4CB9D9B76B5AC64C24CFE7C367B46FA6F06037D945835019D3F1220803BE0A55ADAAAD2EABBDF69A6BA6EA4 (truncated)
	Ticket age= feff
	obfuscated age = 447e2e62
	Client Hello sent
	BND= 258FA2CE9D69253C83646641266B2A81FCEED47348D60E0C7BBB27D2557D1BD2
	Sending Binders
	Client Early Traffic Secret= CF7D980E8213205CFD35C2194FB75F6D1E98215860BB1F7FA5CFDC8DAE48E9F5
	Sending some early data
	Sending Application Message

	GET / HTTP/1.1
	Host: swifttls.org


	Parsing serverHello
	Cipher Suite is TLS_AES_128_GCM_SHA256
	Key Exchange Group is SECP256R1
	PSK Identity= 0
	Server Public Key= 0401D908F018811AF140E2D417EB2713492C146C2B73F78A81DEC6C3F6E2A31D5114207D93EC92AEB03D64DAD11728AAE3A9764DF2473F8CBBB7476C (truncated)

	serverHello= 0200009D0303268C69B38026464DFFE72A496662627EC35798DA3F98437042E39CAF404C888520557742FB051C8ADC0A421E53E1B1B86268B4A1A6CC (truncated)
	Shared Secret= 8C7784C539C0144B8FADCBF065637418F190C49995E79660919E204F05287C2D
	Handshake Secret= 4025A7EE2C1B634C9FC83FDF5CFB2FCB5498EA3F5D019EEDC6D3C1D751C87C47
	Client handshake traffic secret= 5FC1307F4E7ED84B4196B83EA19D69724812C25A571061FB53B5B6E9FD7FCABE
	Server handshake traffic secret= 1E84FEBA7F8D75F756408906C608925F9A6445292BA614BB398E634CF5854B2A
	Early Data Accepted
	Warning - ALPN extension NOT acknowledged by server
	Server Name NOT acknowledged
	Max frag length request NOT acknowledged
	Transcript Hash (CH+SH+EE) = DCB73D7B5416D91546EF7D625FBB6A84105CCCE5F054D753275325A822D394E9
	Send End of Early Data
	Transcript Hash (CH+SH+EE+SF+ED) = FE1FADC8085B3B41A9146647FC9A40F6F2A303533B237112564A2F51F82B64C4
	Server Data is verified
	Client Verify Data= 350E968A15D36F16BC20D80789E9DB2792A2975765F9BE537407165F7E7366B8
	Client application traffic secret= 536F912C98CF4C2D9672DEA57AC8136519607014EFEBBA289FCED97929EA9633
	Server application traffic secret= 6B797DBC7FB2D9F75A877F1D34EE7CACC6D65C847C085331F8941C81F2884E83
	Resumption Handshake concluded
	Early data was accepted
	Waiting for Server input
	Receiving application data (truncated HTML) = 485454502F312E3120323030204F4B0D0A5365727665723A205377696674544C530D0A5374726963
	Alert sent to Server - Close notify
	Connection closed
	
Try it out on your favourite websites. It will abort if TLS1.3 is not supported. 
In a small number of cases it will fail due to receiving a malformed certificate chain from the Server. It is not forgiving of badly 
formed certificate chains, and makes no attempt to fix them.

Also try

	./client tls13.1d.pw
	
Try it a few times - it randomly asks for a HelloRetryRequest and a Key Update, testing this code (but it does not allow resumption). This site also requires that
short records are not padded (that is PAD\_SHORT\_RECORDS is not defined in *tls1_3.h*).

A resumption ticket can be deleted by

	./client -r


See doc/list.txt for some websites that work OK and test different functionality.

## Client side Authentication

A self-signed client certificate and private key can be generated by

	openssl req -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name secp256r1) -keyout mykey.pem -out mycert.pem

and inserted into the file *tls_client_cert.cpp*. Or use the example certificate that is there already.

A way to test less common options is to set up a local openssl server. First generate a self-signed server certificate using something like

	openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

then for example

	openssl s_server -tls1_3 -key key.pem -cert cert.pem -accept 4433 -www

acts as a normal Website, while

	openssl s_server -tls1_3 -verify 0 -key key.pem -cert cert.pem -accept 4433 -www

looks for client side certificate authentication - and the server makes a Certificate Request to the client. We can't control the openssl
debug output, but its better than nothing! The client connects to this local server via

	./client localhost

## Testing Pre-shared keys

Again we will use OpenSSL to mimic a TLS1.3 server

	openssl s_server -tls1_3 -cipher PSK-AES128-GCM-SHA256 -psk_identity 42 -psk 0102030405060708090a0b0c0d0e0f10 -nocert -accept 4433 -www

and connect via

	./client -p 42 localhost

An important setting in *tls1_3.h* is CRYPTO\_SETTING. For the above tests is is assumed that this is set to the default TYPICAL, which allows 
interaction with standard websites. However it may also be set to TINY\_ECC, POST\_QUANTUM and HYBRID. These last three support interaction 
with our own rust server. This setting impacts code size and memory resource allocation. It also controls the type of the self-signed 
certificate provided by the client if it is asked to authenticate. Remember that any changes like this which impact the SAL requires a fresh build.

Note that the HYBRID setting now works using X25519+MLKEM768 for key exchange with an OpenSSL server, and some online servers like www.cloudfare.com 

The client choice of key exchange algorithms, and their preferred ordering, is set in the sal (*tls_sal.cpp*). The chosen CRYPTO\_SETTING
impacts on this ordering. With the default setting the X25519 elliptic curve is preferred.

To test our IBE version of TLS, simply run the TiigerTLS rust server (not openssl!), and then

	./client -i localhost


