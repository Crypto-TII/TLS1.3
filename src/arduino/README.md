
# Configure the Arduino Nano RP2040

This build is specifically for Arduino version of Raspberry Pi Pico (RP2040)

First the board needs to be initialised and locked. To do this install the ArduinoECCX08 library and run the ECCX08SelfSignedCert example program. 

(This example program appears when an MKR1000 board is suggested, and may not appear for the RP2040. However it runs fine on the RP2040).

This program (a) locks the board, and (b) generates a self-signed X.509 certificate, with an associated private key hidden in Slot 0. Copy 
the self-signed certificate and place it into tls_client_cert.cpp where indicated.

Note that the ECC608A chip does a lot of the heavy crypto lifting, especially if the secp256r1 curve is used for certificate signatures.

The key exchange secret is generated in Slot 1. Slot 9 is used for the HMAC calculation. See the ECC608A documentation for more detail.

# Building the client application on an Arduino board.

1.	Create working directory directory with name tiitls
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in all of the TLS1.3 code from the lib/, include/, sal/ and src/arduino directories (but not from subdirectories)
6.	Edit the file core.h to define CORE_ARDUINO (line 31)
7.	Edit the file tls_sockets.h to define TLS_ARDUINO. Optionally set VERBOSITY in tls1_3.h to IO_DEBUG.
8.	Edit the file client.cpp to set your wifi SSID and password (near line 45)
9.	Run py config.py, and select options 2,8,41 and 43. This creates the SAL (in this case using miracl + ECC608A hardware).
10.	Drop the working directory into where the Arduino IDE expects it. 
11.	(In the IDE select File->Preferences and find the Sketchbook location - its the libraries directory off that.)
12.	Open the Arduino app, and look in File->Examples->tiitls, and look for the example "client"
13.	Upload to the board and run it! Tools->Serial Monitor to see the output.

