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

//extern int setserversock(int port);
extern int setclientsock(int port, char *ip);
extern int getIPaddress(char *ip,char *hostname);

// Simple socket class
class Socket
{
    int sock;
public:
    Socket() {sock=0;}

    bool connect(char *host,int port);
    int write(char *buf,int len) {return ::send(sock,buf,len,0);}
    int read(char *buf,int len) {return ::recv(sock,buf,len,0);}
    void close() {::close(sock);}

    ~Socket() {::close(sock);}
};

#ifdef CORE_ARDUINO
typedef WiFiClient Socket;  
#endif

extern void sendOctet(Socket &client,octet *B);
extern void sendLen(Socket &client,int len);
extern int getBytes(Socket &client,char *b,int expected);
extern int getInt16(Socket &client);
extern int getInt24(Socket &client);
extern int getByte(Socket &client);
extern int getOctet(Socket &client,octet *B,int expected);

#endif