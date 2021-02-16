// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include <string.h>
#include "core.h"
#include "tls_logger.h"

#ifdef CORE_ARDUINO
#include "tls_wifi.h"
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

#ifndef CORE_ARDUINO

//extern int setserversock(int port);
extern int setclientsock(int port, char *ip, int toms);
extern int getIPaddress(char *ip,char *hostname);

// Simple socket class, mimics Arduino
class Socket
{
    int sock;
    int toms;
    bool is_af_unix;

private:
    Socket(bool is_af_unix) {
        this->sock = 0;
        this->toms = 5000;
        this->is_af_unix = is_af_unix;
    }

    static int afunix_setclientsock(const char *const socket_path)
    {
        int sock;
        struct sockaddr_un serv_addr;
        if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        {
#if VERBOSITY >= IO_APPLICATION
            logger((char *)"\n Socket creation error \n", NULL, 0, NULL);
#endif
            return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        strcpy(serv_addr.sun_path, socket_path);

        if (::connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        {
#if VERBOSITY >= IO_APPLICATION
            logger((char *)"\nConnection Failed \n", NULL, 0, NULL);
#endif
            return -1;
        }
        return sock;
    }


public:
    bool connect(char *host,int port) {
        if(!this->is_af_unix) {
            char ip[40];
            sock = 0;
            if (!getIPaddress(ip, host))
                return false;
            sock = setclientsock(port, ip, toms);
            if (sock <= 0)
                return false;
            return true;
        } else {
            bool connected = true;
            sock = afunix_setclientsock(host);
            if (sock <= 0) {
                connected = false;
            }
            return connected;
        }
    }

    static Socket InetSocket() {
        return Socket(false);
    }

    static Socket UnixSocket() {
        return Socket(true);
    }

    void setTimeout(int to) {toms=to;}
    int write(char *buf,int len) {return ::send(sock,buf,len,0);}
    int read(char *buf,int len) {return ::recv(sock,buf,len,0);}
    void stop() {::close(sock);}

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