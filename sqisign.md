This describes an experimental configuration, featuring hybrid post quantum key exchange (MLKEM768+X25519), along with fused SQISIGN3+Ed376 digital signatures

The SQISIGN V2 library is presumed to be downloaded and pre-processed into *sqisign.h* and *libsqisign.a*

	// sqisign.h
	#ifndef SQISIGN_H
	#define SQISIGN_H

	#define SQISIGN_LVL3_SECRETKEYBYTES    529
	#define SQISIGN_LVL3_PUBLICKEYBYTES    97
	#define SQISIGN_LVL3_SIGNATUREBYTES    224

	#define SQISIGN_LVL3_ALGNAME    "SQIsign_lvl3"

	#define sqisign_lvl3_keypair    sqisign_lvl3_broadwell_sqisign_keypair

	int sqisign_lvl3_keypair(unsigned char *pk, unsigned char *sk);

	int sqisign_lvl3_sign(unsigned char *sig, const unsigned char *m,
			  unsigned long long mlen, const unsigned char *sk);

	int sqisign_lvl3_verify(const unsigned char *m, unsigned long long mlen,
			    const unsigned char *sig, const unsigned char *pk);
	#endif

**IMPORTANT** Make sure to implement a true random number generator in *tls_sal_mt.xpp* where indicated.

Do a special MIRACL+TLSECC build of the C++ client after setting CRYPTO_SETTING in *tls1_3.h* to POST\_QUANTUM (to allow support for the widest range of signature algorithms)

	bash scripts/build.sh -4

(This script copies *sqisign.h* and *libsqisign.a* into the *build* directory from the place they are kept on your system).

Copy the files *makerootcert.cpp*, *makeintercert.cpp*, *makeleafcert.cpp* into the *build* directory and edit to use *ED376_SQISIGN3* methods as signatures and 
public keys, except for the leaf certificate public key which should be of type *ED25519_MLDSA44*.

	g++ -O2 -DSQISIGN_TEST makerootcert.cpp libtiitls.a core.a tlsecc.a libsqisign.a -lgmp -o makerootcert
	g++ -O2 -DSQISIGN_TEST -DSQISIGN_TEST_X509 makeintercert.cpp libtiitls.a core.a tlsecc.a libsqisign.a -lgmp -o makeintercert
	g++ -O2 -DSQISIGN_TEST -DSQISIGN_TEST_X509 makeleafcert.cpp libtiitls.a core.a tlsecc.a libsqisign.a -lgmp -o makeleafcert

Then 
	./makerootcert
	./makeintercert
	./makeleafcert

It is important to execute these in order.

Now combine the *leaf.crt* and *inter.crt* files to create *certchain.pem*. 

	cat leaf.crt inter.crt > certchain.pem

Copy *certchain.pem* and *leaf.key* to the *servercert* directory. Once there rename *leaf.key* to *server.key*

Important to note that the contents of *root.crt* must be added manually to the *tls_cacerts.cpp* file. 

Rebuild the C++ client.

	bash scripts/build.sh -4

Build and run the Rust server application from *rust/server* and the client from *cpp/build*. The server will use the new certificate chain, and the client will validate it against its built-in copy of the root certificate.
