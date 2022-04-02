First configure and build a rust version of the miracl core library on your local machine. For instructions see https://github.com/miracl/core

Edit the Cargo.toml file in this directory to make sure that its dependency path points to this miracl core library.

Copy the contents of this directory to a working directory.

To build the client program in debug mode

	cargo build

then navigate to target/debug and enter

	./client www.bbc.co.uk

to build in release mode instead

	cargo build --release

and navigate to target/release

On first running a full TLS1.3 handshake is completed. A resumption ticket issued by the website is stored in a file cookie.txt
On running again the ticket is used to resume the connection.

For more details see the readme file in the C++ version
