# TIIGER TLS Rust

Here find a TLS1.3 client and a TLS1.3 server. Both are written in Rust.

<img src="https://img.shields.io/badge/language-rust-blue.svg"/>
<img src="https://img.shields.io/badge/platform-mac | linux | win-lightgrey.svg?style=flat"/>

# Installation

Private keys, server/client certificate chains, and CA root stores are all fixed in the code.

Ideally keys, chains and key stores should be kept in external files, but in an IoT setting there may not be a file system. 
In this code the root certificate store is in the source code file *cacerts.rs*. For the client the private key and certificate are stored in the source code file *clientcert.rs*. 
For the server the private key and certificate are stored in the source code file *servercert.rs*. 

Ensure that the latest version of Rust is installed on your machine. For later tests you will also need to install OpenSSL. First clone the repository and move to 
the *TLS13/rust* directory (where this README is)

Currently the Rust implementation only supports a MIRACL-based SAL. To install from this directory (TLS1.3/rust) proceed as follows. In the unlikely event that yours is a 32-bit environment 
specify *config32* instead.

	git clone https://github.com/miracl/core.git
	cd core/rust
	python3 config64.py test
	cd ../..

To build the client program move to the *client* directory and 

	cargo build

To build in release mode (much faster code)

	cargo build --release

To build and run the server program move to the *server* directory in a new window and 

	cargo run
	
or

	cargo run --release

# Testing

From the client window first try

	cargo run www.bbc.co.uk

or

	cargo run --release www.bbc.co.uk

On first running against a new website a full TLS1.3 handshake is completed. A resumption ticket issued by the website is stored in a file cookie.txt
On running again on the same website the ticket is used to resume the connection. Tickets can be re-used multiple times, but have a limited lifetime.

Old tickets can be removed at any time by entering

	cargo run /r

To see the client capabilities (same for the server) enter

	cargo run --release /s

Note the significant speed-up when in release mode.

Next fire up your favourite browser and navigate to

	https://127.0.0.1:4433

The browser connects to the local server and displays a message. You may need to over-ride a warning from the browser. Observe the number of TLS connections actually made by the browser. In this case 
the ticket is stored as a browser cookie. On a subsequent connection it should perform a resumption handshake.


While in the client window, enter

	cargo run localhost

The local client now connects to the local server. Exit the server program, and edit its *src/config.rs* file to set

	pub const CERTIFICATE_REQUEST: bool=true;

(at the same time it is possible to change other configuration options, for example to provide more debug information)

Now run the server and client again (remove any old tickets first). This time the client responds to the certificate request and authenticates using its own built-in certificate. 

Set CERTIFICATE\_REQUEST back to false and run the server again. Now open a new window and enter

	openssl s_client -tls1_3 -sess_out ticket.pem -host localhost

The OpenSSL client connects to the local server, and accepts and stores a resumption ticket. Now try

	openssl s_client -tls1_3 -sess_in ticket.pem -host localhost
 
and the resumption ticket is used to reconnect.


Both client and server are configured via their *src/config.rs* files. In both can be found the default

	pub const CRYPTO_SETTING: usize = TYPICAL;

For the server this setting controls the certificate chain that the server sends to the client. Currently there
is a choice of four: TYPICAL, TINY_ECC, POST_QUANTUM and HYBRID. TYPICAL uses a self-signed RSA certificate, TINY_ECC
uses a full 3-link chain using only the secp256r1 elliptic curve, POST_QUANTUM uses a 3-link chain using DILITHIUM3, and HYBRID
uses a 3-link chain using secp256r1+DILITHIUM2. In the last three cases we have added the root certificates, which we generated
ourselves, to the root certificate store used by the client.

For the client CRYPTO\_SETTING is used to control the preferred key exchange algorithm, which is X25519 for TYPICAL or TINY\_ECC, 
and kyber768 for POST\_QUANTUM and HYBRID. The ordering of preferences can be changed by editing the SAL (that is the *sal.rs* file).

In most cases it is best to use the same setting for both client and server. If it is desired that the client should interoperate
with standard websites rather than just our own rust server, then its CRYPTO\_SETTING should be set to use TYPICAL. 

To test our IBE version of TLS, simply run the TiigerTLS server, and then

	cargo run /i localhost

For more testing possibilities see the readme file in the C++ version
