# Generating certificate chains *without* using OpenSSL (EXPERIMENTAL!)

This allows experimentation with currently non-standardised digital signature algorithms.

Do a MIRACL-only build of the C++ client after setting CRYPTO_SETTING in *tls1_3.h* to POST_QUANTUM

Copy the files *makerootcert.cpp*, *makeintercert.cpp*, *makeservercert.cpp* from here into the build directory and edit where indicated to specify your certificate details and preferred signature types

	g++ -O2 makerootcert.cpp libtiitls.a core.a -o makerootcert
	g++ -O2 makeintercert.cpp libtiitls.a core.a -o makeintercert
	g++ -O2 makeservercert.cpp libtiitls.a core.a -o makeservercert

Then 

	./makerootcert
	./makeintercert
	./makeservercert

Ignore debugging output

The following files should be created

*inter.crt*  *root.crt*  *server.crt* *inter.key*  *root.key*  *server.key*

Certificates can be examined by pasting the base64 in the .crt files into https://lapo.it/asn1js/

Use OpenSSL v3.5 only to verify that the certificate chain is valid.

	openssl verify -CAfile root.crt -untrusted inter.crt server.crt

It should respond with

	server.crt: OK

Now combine the *server.crt* and *inter.crt* files to create *certchain.pem*. 

	cat server.crt inter.crt > certchain.pem

Copy *certchain.pem*, *server.key* and *root.crt* to the *servercert* directory. Proceed as indicated in MAKECERT.md

Important to note that the contents of *root.crt* must be added manually to the *tls_cacerts.cpp* and *cacert.rs* files

Finally rebuild the client and server applications (maybe after resetting CRYPTO_SETTING and using a different build for the C++ client). The server can use the new certificate chain, and the client will validate it against its built-in copy of the root certificate.


