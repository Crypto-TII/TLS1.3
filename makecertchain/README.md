# Generating certificate chains *without* using OpenSSL (EXPERIMENTAL!)

This allows experimentation with currently non-standardised digital signature algorithms.

**IMPORTANT** Make sure to implement a true random number generator in *tls_sal_m.xpp* where indicated.

Do a MIRACL-only build of the C++ client after setting CRYPTO_SETTING in *tls1_3.h* to HYBRID (to allow support for the widest range of signature algorithms)

Copy the files *makerootcert.cpp*, *makeintercert.cpp*, *makeleafcert.cpp* from here into the build directory and edit where indicated to specify your certificate details and preferred signature types

	g++ -O2 makerootcert.cpp libtiitls.a core.a -o makerootcert
	g++ -O2 makeintercert.cpp libtiitls.a core.a -o makeintercert
	g++ -O2 makeleafcert.cpp libtiitls.a core.a -o makeleafcert

Then 
	./makerootcert
	./makeintercert
	./makeleafcert

It is important to execute these in order. Ensure that the Public key embedded in a certificate is compatible with the signature appended to the next certificate in the chain.

Ignore any debugging output

The following files should be created

*inter.crt*  *root.crt*  *leaf.crt*  *inter.key*  *root.key*  *leaf.key*

Certificates can be examined by pasting the base64 in the .crt files into https://lapo.it/asn1js/

Internal consistency tests are applied to ensure the integrity of the certificate chain. For independent verification it is possible to use OpenSSL v3.5 (for OpenSSL supported crypto algorithms).

	openssl verify -CAfile root.crt -untrusted inter.crt leaf.crt

It should respond with

	leaf.crt: OK

Now combine the *leaf.crt* and *inter.crt* files to create *certchain.pem*. 

	cat leaf.crt inter.crt > certchain.pem

Copy *certchain.pem* and *leaf.key* to the *servercert* directory. Once there rename *leaf.key* to *server.key*

Important to note that the contents of *root.crt* must be added manually to the *tls_cacerts.cpp* and *cacert.rs* files. Use the provided *convert.cpp* tool to automatically generate C++ and Rust compatible code.

Rebuild the C++ client.

Move to the directory *rust/server/src* and edit the *config.rs* file and ensure the following setting. Its the default.

	pub const SERVER\_CERT:usize= FROM_FILE; 

If your chain uses post-quantum or hybrid primitives also set

	pub const CRYPTO_SETTING: usize = HYBRID; 

Finally run the Rust server application from *rust/server*. The server can use the new certificate chain, and the client will validate it against its built-in copy of the root certificate.

To update the chain to use a new leaf certificate (perhaps when the old one expires) with the same root and intermediate certificates, just run the *makeleafcert* application again and replace 
*certchain.pem* and *leaf.key*.

Client-side certificates can be created in a similar way.
