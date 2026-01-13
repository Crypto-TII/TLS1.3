# Generating certificate chains *without* using OpenSSL (EXPERIMENTAL!)

This allows experimentation with currently non-standardised digital signature algorithms.

**IMPORTANT** Make sure to implement a true random number generator in *tls_sal_m.xpp* where indicated.

Do a MIRACL-only build of the C++ client after setting CRYPTO_SETTING in *tls1_3.h* to POST_QUANTUM

Copy the files *makerootcert.cpp*, *makeintercert.cpp*, *makeservercert.cpp* from here into the build directory and edit where indicated to specify your certificate details and preferred signature types

	g++ -O2 makerootcert.cpp libtiitls.a core.a -o makerootcert
	g++ -O2 makeintercert.cpp libtiitls.a core.a -o makeintercert
	g++ -O2 makeservercert.cpp libtiitls.a core.a -o makeservercert

Then 

	./makerootcert
	./makeintercert
	./makeservercert

It is important to execute these in order. Ensure that the Public key embedded in a certificate is compatible with the signature appended to the next certificate in the chain.

Ignore any debugging output

The following files should be created

*inter.crt*  *root.crt*  *server.crt*  *inter.key*  *root.key*  *server.key*

Certificates can be examined by pasting the base64 in the .crt files into https://lapo.it/asn1js/

Use OpenSSL v3.5 only to verify that the certificate chain is valid.

	openssl verify -CAfile root.crt -untrusted inter.crt server.crt

It should respond with

	server.crt: OK

Now combine the *server.crt* and *inter.crt* files to create *certchain.pem*. 

	cat server.crt inter.crt > certchain.pem

Copy *certchain.pem*, *server.key* and *root.crt* to the *servercert* directory. 

Important to note that the contents of *root.crt* must be added manually to the *tls_cacerts.cpp* and *cacert.rs* files. Use the provided *convert.cpp* tool to automatically generate C++ and Rust compatible code.

Rebuild the C++ client.

Move to the directory *rust/server/src* and edit the *config.rs* file and ensure the following settings

	pub const SERVER\_CERT:usize= FROM_FILE; 
	pub const CRYPTO_SETTING: usize = POST_QUANTUM;

Finally build the Rust server application. The server can use the new certificate chain, and the client will validate it against its built-in copy of the root certificate.


