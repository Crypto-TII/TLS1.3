// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include <string.h>
#include <time.h>
#include "core.h"
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netdb.h>
#include <netinet/in.h>

using namespace core;

extern int setserversock(int port);
extern int setclientsock(int port, char *ip);
extern void sendOctet(int sock,octet *B);
extern void sendLen(int sock,int len);
extern int getBytes(int sock,char *b,int expected);
extern int getInt16(int sock);
extern int getInt24(int sock);
extern int getByte(int sock);
extern int getOctet(int sock,octet *B,int expected);
extern int getIPaddress(char *ip,char *hostname);

#endif