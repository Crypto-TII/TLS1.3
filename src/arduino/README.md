# Building the client application on an Arduino board (here Arduino Nano 33 IoT)

1.	Create working directory directory with name tiitls
2.	Copy in all from the cpp directory of https://github.com/miracl/core
3.	Copy in all from the arduino directory of https://github.com/miracl/core
4.	(If ever asked to overwrite a file, go ahead and overwrite it)
5.	Copy in all of the code from the lib/, include/, sal/ and src/arduino directories (but not from subdirectories)
6.	Edit the file core.h to define CORE_ARDUINO (line 31)
7.	Edit the file tls_sockets.h to define TLS_ARDUINO. Optionally set VERBOSITY in tls1_3.h to IO_DEBUG.
8.	Edit the file client.cpp to set your wifi SSID and password (near line 45)
9.	Run py config.py, and select options 2,8,41 and 43. This creates the SAL (in this case using miracl + ECC608A hardware).
10.	Drop the working directory into where the Arduino IDE expects it. 
11.	(In the IDE select File->Preferences and find the Sketchbook location - its the libraries directory off that.)
12.	Open the Arduino app, and look in File->Examples->tiitls, and look for the example "client"
13.	Upload to the board and run it! Tools->Serial Monitor to see the output

