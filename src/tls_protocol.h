/**
 * @file tls_protocol.h
 * @author Mike Scott
 * @brief TLS 1.3 main client-side protocol functions
 *
 */
// Main TLS 1.3 Protocol

#ifndef TLS_PROTOCOL_H
#define TLS_PROTOCOL_H

#include "tls_keys_calc.h"
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_client_send.h"
#include "tls_tickets.h"
#include "tls_logger.h"

using namespace core;

/**	@brief TLS 1.3 full handshake
 *
	@param client the socket connection to the Server
    @param hostname the host name (URL) of the server
    @param RNG a random number generator
    @param favourite_group our preferred group, which may be updated on a handshake retry
    @param CPB the client capabilities structure
    @param IO a workspace octet to buffer Server input
    @param RMS a returned Resumption Master secret
    @param T a returned resumption ticket
    @param K_send a crypto context for encrypting application traffic to the server
    @param K_recv a crypto context for decrypting application traffic from the server
    @param STS server application traffic secret - may be updated
 */
extern int TLS13_full(Socket &client,char *hostname,csprng &RNG,int &favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS);

/**	@brief TLS 1.3 resumption handshake
 *
	@param client the socket connection to the Server
    @param hostname the host name (URL) of the server
    @param RNG a random number generator
    @param favourite_group our preferred group
    @param CPB the client capabilities structure
    @param IO a workspace octet to buffer Server input
    @param RMS a returned Resumption Master secret
    @param T a returned resumption ticket
    @param K_send a crypto context for encrypting application traffic to the server
    @param K_recv a crypto context for decrypting application traffic from the server
    @param STS server application traffic secret - may be updated
    @param EARLY early data that can be immediately sent to the server (0-RTT data) 
 */
extern int TLS13_resume(Socket &client,char *hostname,csprng &RNG,int favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS,octet &EARLY);

#endif