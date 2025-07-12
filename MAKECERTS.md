# Certificate generation

Python scripts are provided to use the OpenSSL tool (V3.5+) to generate Certificate Chains for use by TiigerTLS

A TLS-friendly certificate chain consists of 3 links, the end-user certificate, the intermediate certificate and the root certificate. 
The end-user is usually the TLS server, but can also optionally be a TLS client. For clarity here we assume it is the server.

The root certificate belongs to an external Certificate Authority, like Lets Encrypt. The intermediate certificate typically 
belongs to the deployer's organisation. The server certificate is typically for day by day use by the deployer's TLS server.

The server certificate is signed by the intermediate's secret key, and the intermediate certificate is signed by the root's secret key.
The root certificate is signed by its own secret key (it is self-signed).

# Where are the secret keys?

Each certificate embeds a public key. The related secret key must be stored securely. In the case of a root key, it is probably stored 
inside of an air-gapped HSM (Hardware Security Module), and rarely used. The intermediate secret key is kept secure by the deployer's 
organisation, maybe encrypted and only decrypted when a server certificate needs to be renewed. The server secret key is the most 
exposed, but typically has a much shorter lifetime. It must be available 24/7 for use by the TLS server.

# TiigerTLS certificate chains

We do not control a global Certificate authority. But in a closed-world setting we can create our own. In the *servercert* directory 
there is
an *server* directory, inside of which there is an *intermediate* directory, inside of which there is a *root* directory. In each of 
these is a Python script which can generate a suitable certificate. To create a full chain in a closed world setting, start from 
the *root* directory and work back. Measures should be taken to further protect the associated secret keys as suggested above.

If using a global Certificate Authority work back from the *intermediate* directory, and arrange to get the intermediate certificate signed
by that external authority. Similarly we work back from the *server* directory if the intermediate authority is outside of our direct 
control. Typically a server only needs to be concerned with updating its server certificate and secret by re-running its Python script, and 
getting that certificate signed by the intermediate authority.

After a chain has been created the *servercert* directory should contain the files *certchain.pem*, and *server.key* to be picked up by 
the TLS
server, and the root certificate *root.crt* which must then be added to the TLS client's store of recognised Certificate Authority's 
self-signed certificates, if it is not there already.

# The scripts

The Python scripts provided in each directory generate digitally signed certificates, using one of a number of digital signature algorithms.
The user is encouraged to edit these scripts as desired.
Currently the choice of signature algorithms is between RSA1024, RSA2048, RSA4096, ED25519, ED448, NIST256, NIST384 and MLDSA65, but more 
can be added. The descriptive properties (Country, Common Name etc) to be included in each certificate can also be chosen.

# Short-lived Certificates

At regular short intervals the server might be restarted to renew a short-lived server certificate. This requires first re-running only 
the *server.py* script to generate new *server.key* and *certchain.pem* files.

# Quickstart Demo

Download the repository to a working directory. Move to the *servercert/server/intermediate* and execute

	python3 intermediate.py NIST384
	
Next drop back one level to the *server* directory and execute

	python3 server.py NIST256 sha384
	
(Note that here we want the server certificate to be signed by esdsa-with-sha384, rather than the ecdsa-with-sha256 default)

Proceed to the directory *clientcert/client/intermediate* and execute

	python3 intermediate.py ED448
	
Drop back one level to the *client* directory and execute

	python3 client.py ED25519
	
Note that an RSA 2048-bit root certificate and its associated secret come preinstalled. The root certificate is already inserted into the certificate stores of both the TiigerTLS server and the TiigerTLS client. Here we will be using the same root certificate authority for both servers and clients, but this is not a requirement.

Certificate chains and server/client secrets are now generated and we can attempt a fully authenticated communication between the Rust server and the Rust client.

Move to the directory *rust/server/src* and edit the *config.rs* file and ensure the following settings

	pub const CERTIFICATE_REQUEST: bool=true;
	pub const SERVER\_CERT:usize= FROM_FILE; 
	pub const CRYPTO_SETTING: usize = EDDSA;
	
Execute

	cargo run

Now move to a new window and navigate to *rust/client/src* and edit the *config.rs* file and ensure the following settings

 	pub const CLIENT\_CERT:usize= FROM_FILE; 
	pub const CRYPTO_SETTING: usize = EDDSA;

Finally run the client and make a fully authenticated TLS1.3 connection

	cargo run localhost




	


	
		

