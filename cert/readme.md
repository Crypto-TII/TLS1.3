# Certificate generation

Python scripts are provided to use the OpenSSL tool (V3.5+) to generate Certificate Chains for use by TiigerTLS

A TLS-friendly certificate chain consists of 3 links, the end-user certificate, the intermediate certificate and the root certificate. 
The end-user is usually the TLS server, but can also optionally be a TLS client. For clarity here we assume it is the server.

The root certificate belongs to an external Certificate Authority, like Lets Encrypt. The intermediate certificate typically 
belongs to the deployer's organisation. The end-user certificate is typically for day by day use by the deployer's TLS server.

The end-user certificate is signed by the intermediate's secret key, and the intermediate certificate is signed by the root's secret key.
The root certificate is signed by its own secret key (it is self-signed).

# Where are the secret keys?

Each certificate embeds a public key. The related secret key must be stored securely. In the case of a root key, it is probably stored 
inside of an air-gapped HSM (Hardware Security Module), and rarely used. The intermediate secret key is kept secure by the deployer's 
organisation, maybe encrypted and only decrypted when an end-user certificate needs to be updated. The end-user secret key is the most 
exposed, but typically has a much shorter lifetime. It must be available 24/7 for use by the TLS server.

# TiigerTLS certificate chains

We do not control a global Certificate authority. But in a closed-world setting we can create our own. In the *cert* directory there is
an *enduser* directory, inside of which there is an *intermediate* directory, inside of which there is a *root* directory. In each of 
these is a Python script which can generate a suitable certificate. To create a full chain in a closed world setting, start from 
the *root* directory and work back. Measures should be taken to further protect the associated secret keys as suggested above.

If using a global Certificate Authority work back from the *intermediate* directory, and arrange to get the intermediate certificate signed
by that external authority. Similarly we work back from the *enduser* directory if the intermediate authority is outside of our direct control.
Typically an end-user only needs to be concerned with updating its end-user certificate and secret by re-running its Python script, and 
getting that certificate signed by the intermediate authority.

After a chain has been created the *cert* directory should contain the files *certchain.pem*, and *enduser.key* to be picked up by the TLS
server, and the root certificate *root.crt* which must then be added to the TLS client's store of recognised Certificate Authority's 
self-signed certificates, if it is not there already.

# The scripts

The Python scripts provided in each directory generate digitally signed certificates, using one of a number of digital signature algorithms.
The user is encouraged to edit these scripts as desired.
Currently the choice of signature algorithms is between RSA1024, RSA2048, RSA4096, ED25519, ED448, NIST256, NIST384 and MLDSA65, but more 
can be added. The descriptive properties (Country, Common Name etc) to be included in each certificate can also be chosen.

# Quickstart

Copy the repository to a working directory

Move to the *cert/enduser/intermediate/root* directory and execute

	python3 root.py RSA2048

Move down to the *cert/enduser/intermediate* directory and execute

	python3 intermediate.py NIST384

Move down to the *cert/enduser* directory and execute

	python3 enduser.py NIST256

Move down to the *cert* directory and find the files *certchain.pem*, *enduser.key* and *root.crt*
