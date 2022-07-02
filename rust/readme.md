# Installation

Here find a TLS1.3 client and a (rather rudimentary) TLS1.3 server. Both are written in Rust.

Ensure that the latest version of Rust is installed on your machine. For later tests you will also need to install OpenSSL.

Next configure and build a Rust version of the miracl core library on your local machine. For instructions see https://github.com/miracl/core


Copy the contents of this directory plus subdirectories to a working directory.

In a new command window navigate to the *client* sub-directory and edit the *Cargo.toml* file and make sure that its dependency path points to the miracl core library.

To build the client program in debug mode enter

	cargo build

To build in release mode (much faster)

	cargo build --release

In a new command window navigate to the *server* sub-directory and again edit its *Cargo.toml* file and make sure that its dependency path points to the miracl core library.
This time build and execute the server by

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


Next fire up your favourite browser and navigate to

	https://127.0.0.1:4433

The browser connects to the local server and displays a message. Observe the number of TLS connections actually made by the browser. In this case the ticket is stored as a browser cookie.


While still in the client window, enter

	cargo run localhost

The local client now connects to the local server. Exit the server program, and edit its *src/config.rs* file to set

	pub const CERTIFICATE_REQUEST: bool=true;

(at the same time it is possible to change other configuration options, for example to provide more debug information)

Now run the server and client again. This time the client responds to the certificate request and authenticates using its own built-in certificate. 

With the the server running, open a new window and enter

	openssl s_client -tls1_3 -sess_out ticket.pem -host localhost

The OpenSSL client connects to the local server, and accepts and stores a resumption ticket. Now try

	openssl s_client -tls1_3 -sess_in ticket.pem -host localhost
 
and the resumption ticket is used to reconnect.


For more testing possibilities see the readme file in the original C++ version
