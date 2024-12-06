
# Configure the Arduino Nano RP2040

This build is specifically for the Arduino Nano version of the Raspberry Pi Pico (RP2040). Please use version 2.x.x of the Arduino IDE.

First the board needs to be initialised and locked. To do this install the ArduinoECCX08 library and run the ECCX08SelfSignedCert example program. 

(This example program appears when an MKR1000 board is suggested, and may not appear for the RP2040. However it runs fine on the RP2040).

This program (a) locks the board, and (b) generates a self-signed X.509 certificate, with an associated private key hidden in Slot 0. Copy 
the self-signed certificate and place it into tls_client_cert.cpp where indicated.

Note that the ECC608A chip does a lot of the heavy crypto lifting, especially if the secp256r1 curve is used for certificate signature verification.

The key exchange secret is generated in Slot 1. Slot 9 is used for the HMAC calculation. See the ECC608A documentation for more detail.

# Building the client application on the Arduino Nano RP2040 board.

1.	Create working directory directory with name tiitls
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in all of the TLS1.3 C++ code from the lib/, lib/ibe, include/, sal/ and src/arduino directories (but not from subdirectories)
6.	Edit the file core.h to define CORE_ARDUINO (line 31)
7.	Edit the file tls_octads.h to define TLS_ARDUINO (line 13). 
8.	Edit tls1_3.h. Define VERBOSITY as IO_DEBUG for more debug output. Decide on CRYPTO_SETTING. Stack only, or Stack plus heap. 
9.	Edit the file client.cpp to set your wifi SSID and password (near line 150)
10.	Run python3 config.py, and select options 2, 8, 31, 42 and 44. This creates the default SAL (in this case using miracl + ECC608A hardware).
11.	Drop the working directory into where the Arduino IDE expects it. 
12.	(In the IDE select File->Preferences and find the Sketchbook location - its the libraries directory off that.)
13.	Open the Arduino app, and look in File->Examples->tiitls, and look for the example "client"
14.	Upload to the board and run it. Open Tools->Serial Monitor to see the output. 
15.	Enter URL (e.g. www.bbc.co.uk) when prompted, and press return. A full TLS1.3 handshake followed by a resumption is attempted.
16.	Click on Clear Output and Send to repeat for a different URL (or click Send again to see SAL capabilities).

or before executing step 10, search for !!!!!!!! in config.py (around line 1020) and make changes as indicated. 
If using miracl alone, without hardware support, option 3 must be selected as well.
If using assembly language code for X25519, copy x25519.S from https://github.com/pornin/x25519-cm0/blob/main/src/x25519-cm0.S
into working directory and remove option 2. This creates the SAL (in this case using miracl + ECC608A hardware + Pornin's x25519).
If experimenting with post-quantum primitives, also select options 46 and 47, for Dilithium and Kyber support.

or copy into the project all from c32 and include32 directories of https://github.com/mcarrickscott/TLSECC, edit config.py at !!!!!!!!!
to use faster elliptic curve code from TLSECC project, and select only options 31, 42 and 44. This method works well with the Raspberry Pi
Pico 2 W device, which does not support ECC608A hardware. We observe that on this device the crypto is about 1.5 times faster on the ARM core
compared to the RISC-V core.

(Sometimes the wifi works better from wifiNINA.h rather than wifi.h. See tls_wifi.h)

The example TLS1.3 client code first connects to the wireless network, and after that it should connect to standard websites, as
long as they support TLS1.3. The example program first makes a full TLS handshake, and exits after receiving some HTML from the server.
Then after a few seconds, if it has received a resumption ticket, it attempts a resumption handshake.

The client can also be run in conjunction with our Rust server. Make sure that the CRYPTO\_SETTING parameter is the same for both client 
and server. In our experimental set-up, the rust server runs directly from Windows (not WSL), looking for connections on port 4433. Run 
ipconfig to get the IP address of the server on the local network, which might look something like 192.168.1.186. Then run the client from 
the Arduino IDE, and when prompted enter for example 192.168.1.186:4433. The client should now connect to the server. It may however be 
necessary to undefine CHECK_NAME_IN_CERT in tls1_3.h

Note that some servers will reject a resumption handshake if the device's internal clock is not initialised to the current time.

