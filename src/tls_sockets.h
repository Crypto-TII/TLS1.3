/**
 * @file tls_sockets.h
 * @author Mike Scott
 * @brief set up sockets for reading and writing
 *
 */

// Set up and read/write sockets

#ifndef TLS_SOCKETS_H
#define TLS_SOCKETS_H

#include <string.h>
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

#ifndef CORE_ARDUINO

/**	@brief create a client socket 
 *
	@param port the TCP/IP port on which to connect
    @param ip the IP address with which to connect
    @param toms the time-out period in milliseconds
    @return the socket handle
 */
extern int setclientsock(int port, char *ip, int toms);

/**	@brief get the IP address from a URL
 *
    @param ip the IP address
    @param hostname the input Server name (URL)
    @return 1 for success, 0 for failure
 */
extern int getIPaddress(char *ip,char *hostname);

// Simple socket class, mimics Arduino
/**
 * @brief Socket instance */
class Socket
{
    int sock;     /**< the socket handle */
    int toms;     /**< the socket time-out in milliseconds */
    bool is_af_unix;  /**< Is it an AF_UNIX socket? */

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

/**	@brief send an octet over a socket 
 *
	@param client the socket connection to the Server
    @param B the octet to be transmitted
 */
extern void sendOctet(Socket &client,octad *B);

/**	@brief send a 16-bit integer as an octet to Server
 *
	@param client the socket connection to the Server
    @param len the 16-bit integer to be encoded as octet and transmitted
 */
extern void sendLen(Socket &client,int len);

/**	@brief receive bytes over a socket sonnection
 *
	@param client the socket connection to the Server
    @param b the received bytes
    @param expected the number of bytes expected
    @return -1 on failure, 0 on success
 */
extern int getBytes(Socket &client,char *b,int expected);

/**	@brief receive 16-bit integer from a socket
 *
	@param client the socket connection to the Server
    @return a 16-bit integer
 */
extern int getInt16(Socket &client);

/**	@brief receive 24-bit integer from a socket
 *
	@param client the socket connection to the Server
    @return a 24-bit integer
 */
extern int getInt24(Socket &client);

/**	@brief receive a single byte from a socket
 *
	@param client the socket connection to the Server
    @return a byte
 */
extern int getByte(Socket &client);

/**	@brief receive an octet from a socket
 *
	@param client the socket connection to the Server
    @param B the output octet
    @param expected the number of bytes expected
    @return -1 on failure, 0 on success
 */
extern int getOctet(Socket &client,octad *B,int expected);

#endif