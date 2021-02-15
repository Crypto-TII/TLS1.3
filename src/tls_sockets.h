// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include <string.h>
#include "core.h"
#ifdef CORE_ARDUINO
#include <WiFi.h>
#else
#include <time.h>
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>
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
    bool connected;

private:
    Socket(int sock, int toms, bool connected){
        this->sock = sock;
        this->toms = 5000;
        this->connected = connected;
    }

    static int afunix_setclientsock(const char *const socket_path)
    {
        int sock;
        struct sockaddr_un serv_addr;
        if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        {
            printf("\n Socket creation error \n");
            return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        strcpy(serv_addr.sun_path, socket_path);

        if (::connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
            printf("\nConnection Failed \n");
            return -1;
        }
        return sock;
    }


    static Socket afunix_connect(const char *const socketPath) {
        int toms = 10000;
        bool connected = true;
        int sock= afunix_setclientsock(socketPath);
        if (sock<=0) {
            connected = false;
        }
        return Socket(sock, toms, connected);
    }



public:
    static Socket InetSocket(char *host, int port) {
        char ip[40];
        int sock = 0;
        int toms = 10000;
        bool connected = true;
        if (!getIPaddress(ip, host)) {
            connected = false;
        }
        if(connected) {
            sock = setclientsock(port, ip, toms);
        }
        if (sock <= 0) {
            connected = false;
        }

        return Socket(sock, toms, connected);
    }

    static Socket UnixSocket(const char *const path) {
        return afunix_connect(path);
    }
public:

    void setTimeout(int to) {toms=to;}
    int write(char *buf,int len) {return ::send(sock,buf,len,0);}
    int read(char *buf,int len) {return ::recv(sock,buf,len,0);}
    void stop() {::close(sock);}

    ~Socket() {::close(sock);}

    bool isConnected() {
        return connected;
    }
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