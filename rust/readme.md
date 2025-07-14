# TIIGER TLS Rust

Here find a TLS1.3 client and a TLS1.3 server. Both are written in Rust.

<img src="https://img.shields.io/badge/language-rust-blue.svg"/>
<img src="https://img.shields.io/badge/platform-mac | linux | win-lightgrey.svg?style=flat"/>

# Installation

Server and client private keys and certificate chains are either fixed in the code or read from 
external files. To create your own, see *MAKECERTS.md*

The long-term global store of Certificate Authority root certificates can be found in the source code files *cacerts.rs*, created 
using the *convert.cpp* utility.

Ideally keys, chains and key stores should all be kept in external files, but in an IoT setting there may not be a file system. 
So in this Rust code the server and client private keys and certificates can be stored directly in the 
source code files *clientcert.rs* and *servercert.rs*

Ensure that the latest version of Rust is installed on your machine. For later tests you will also need to install OpenSSL 3.5+. 
First clone the repository and move to the *TLS13/rust* directory (where this README is)

The Rust implementation uses a SAL based on the MIRACL and TLSECC cryptographic libraries, where TLSECC supports the elliptic 
curve cryptography and MIRACL supports everything else. To install from this directory (TLS1.3/rust) proceed as follows. In the 
unlikely event that yours is a 32-bit environment change 64 to 32 in two places.

	git clone https://github.com/miracl/core.git
	cd core/rust
	python3 config64.py 31 42 44
	cd ../..
	git clone https://github.com/mcarrickscott/TLSECC
	cd TLSECC
	cargo new --lib tlsecc
	cd tlsecc/src
	cp ../../rust64/* .
	cd ../../..

To build the client program move to the *client* directory. Check that the *Cargo.toml* file has the correct path to the MIRACL 
and TLSECC libraries. Then 

	cargo build

To build in release mode (much faster code)

	cargo build --release

To build and run the server program move to the *server* directory in a new window. Again check that the *Cargo.toml* file has 
the correct path to the MIRACL and TLSECC libraries. Then 

	cargo run
	
or

	cargo run --release

# Testing

From the client window first try

	cargo run www.bbc.co.uk

or

	cargo run --release www.bbc.co.uk

On first running against a new website a full TLS1.3 handshake is completed. A resumption ticket issued by the website is stored in a 
file cookie.txt. On running again on the same website the ticket is used to resume the connection. Tickets can be re-used multiple 
times, but have a limited lifetime.

Old tickets can be removed at any time by entering

	cargo run /r

To see the client capabilities (same for the server) enter

	cargo run --release /s

Note the significant speed-up when in release mode.

Next fire up your favourite browser and navigate to

	https://127.0.0.1:4433

The browser connects to the local server and displays a message. You may need to over-ride a warning from the browser. 
It is not happy with our self-signed certificate.
In this case the ticket is stored as a browser cookie. On a subsequent connection it 
should perform a resumption handshake.


While in the client window, enter

	cargo run localhost

The local client now connects to the local server. Exit the server program, and edit its *src/config.rs* file to set

	pub const CERTIFICATE_REQUEST: bool=true;

(at the same time it is possible to change other configuration options, for example to provide more debug information)

Now run the server and client again (remove any old tickets first). This time the client responds to the certificate request and 
authenticates using its own built-in certificate. 

Set CERTIFICATE\_REQUEST back to false and run the server again. Now open a new window and enter

	openssl s_client -tls1_3 -sess_out ticket.pem -host localhost

The OpenSSL client connects to the local server, and accepts and stores a resumption ticket. Now try

	openssl s_client -tls1_3 -sess_in ticket.pem -host localhost
 
and the resumption ticket is used to reconnect.


Both client and server are configured via their *src/config.rs* files. In both can be found the default

	pub const CRYPTO_SETTING: usize = TYPICAL;

For the server this setting controls the certificate chain that the server sends to the client. Currently there
is a choice of five: TYPICAL, TINY_ECC, EDDSA, POST_QUANTUM and HYBRID. TYPICAL uses a self-signed RSA certificate, TINY_ECC
uses a full 3-link chain using only the secp256r1 elliptic curve, EDDSA uses the superior EdDSA signature algorithm, POST_QUANTUM 
uses a 3-link chain using MLDSA65, and HYBRID
uses a 3-link chain using secp256r1+MLDSA44. In the last four cases we have added the root certificates, which we generated
ourselves, to the root certificate store used by the client.

For the client CRYPTO\_SETTING is used to control the preferred key exchange algorithm, which is X25519 for TYPICAL, TINY\_ECC and EDDSA 
and MLKEM768 for POST\_QUANTUM and X25519+MLKEM768 for HYBRID. The ordering of preferences can be changed by editing the SAL (that is 
the *sal.rs* file).

Note that the HYBRID setting for the client now works with many online servers like www.cloudfare.com 

In most cases it is best to use the same setting for both client and server. If it is desired that the client should interoperate
with standard websites rather than just our own rust server, then its CRYPTO\_SETTING should be set to use TYPICAL. 

To test our IBE version of TLS, simply run the TiigerTLS server, and then from the client window

	cargo run /i localhost

For more testing possibilities see the readme file in the C++ version
