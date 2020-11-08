// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include "core.h"

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


#endif