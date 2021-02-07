// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include <string.h>
#include <time.h>
#include "core.h"
#ifdef CORE_ARDUINO
#include <WiFi.h>
#else
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netdb.h>
#include <netinet/in.h>
#endif

using namespace core;

#ifdef CORE_ARDUINO
typedef WiFiClient Socket;  
#else

//extern int setserversock(int port);
extern int setclientsock(int port, char *ip, int toms);
extern int getIPaddress(char *ip,char *hostname);

// Simple socket class
class Socket
{
    int sock;
    int toms;
public:
    Socket() {sock=0; toms=10000; }

    bool connect(char *host,int port);
    void setTimeout(int to) {toms=to;}
    int write(char *buf,int len) {return ::send(sock,buf,len,0);}
    int read(char *buf,int len) {return ::recv(sock,buf,len,0);}
    void close() {::close(sock);}

    ~Socket() {::close(sock);}
};
#endif


extern void sendOctet(Socket &client,octet *B);
extern void sendLen(Socket &client,int len);
extern int getBytes(Socket &client,char *b,int expected);
extern int getInt16(Socket &client);
extern int getInt24(Socket &client);
extern int getByte(Socket &client);
extern int getOctet(Socket &client,octet *B,int expected);

#endif