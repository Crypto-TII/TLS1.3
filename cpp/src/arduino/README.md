# Configure the Raspberry Pi Pico 2W

This build is specifically for the Raspberry Pi Pico 2W (RP2350). Please use version 2.x.x of the Arduino IDE.

# Building the client application on the Raspberry Pi Pico 2W board.

1.	Create working directory directory with name tiitls
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in all of the TLS1.3 C++ code from the lib/, lib/ibe, include/, sal/ and src/arduino directories (but not from subdirectories)
6.	Edit the file core.h to define CORE_ARDUINO (line 31)
7.	Edit the file tls_octads.h to define TLS_ARDUINO (line 13). 
8.	Copy in all from the c32/, include/ and include32/ directories of https://github.com/mcarrickscott/TLSECC.
9.	Optionally edit tls1_3.h. Define VERBOSITY as IO_DEBUG for more debug output. Decide on initial CRYPTO_SETTING. Stack only, or Stack plus heap. 
10.	Edit the file client.cpp to set your wifi SSID and password (near line 150)
11.	Run python3 config.py, and select options 31, 42 and 44 (and 46 and 47 if you wish to try post quantum methods). This creates the default SAL (in this case using miracl + TLSECC).
12.	Drop the working directory into where the Arduino IDE expects it. (In the IDE select File->Preferences and find the Sketchbook location - its the libraries directory off that.)
13.	Open the Arduino app, and look in File->Examples->tiitls, and look for the example "client"
14.	Upload to the board and run it. Open Tools->Serial Monitor to see the output. 
15.	Enter URL (e.g. www.bbc.co.uk) when prompted, and press return. A full TLS1.3 handshake followed by a resumption is attempted.
16.	Click on Clear Output and repeat for a different URL (or just press return to see SAL capabilities).

We observe that on this device the crypto is about 1.5 times faster on the ARM core compared to the RISC-V core.

The example TLS1.3 client code first connects to the wireless network. Next the client
attempts to use an online time server to access epoch time, and use that to set the clock. After that it should 
connect to standard websites, as long as they support TLS1.3. The example program first makes a full TLS handshake, 
and exits after receiving some HTML from the server. Then after a few seconds, if it has received a resumption 
ticket, it attempts a resumption handshake.

The client can also be run in conjunction with our Rust server. Make sure that the CRYPTO\_SETTING parameter is the 
same for both client and server. In our experimental set-up, the rust server runs directly from Windows (not WSL), 
looking for connections on port 4433. Run ipconfig to get the IP address of the server on the local network, which 
might look something like 192.168.1.186. Then run the client from the Arduino IDE, and when prompted enter for 
example 192.168.1.186:4433. The client should now connect to the server. It will however be 
necessary to undefine CHECK_NAME_IN_CERT in tls1_3.h and rebuild the application for this to work correctly.
