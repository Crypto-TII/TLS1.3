// Main TLS 11.3 Protocol

#ifndef TLS_PROTOCOL_H
#define TLS_PROTOCOL_H

#include "tls_keys_calc.h"
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_client_send.h"
#include "tls_tickets.h"
#include "tls_logger.h"

using namespace core;

extern int TLS13_full(Socket &client,char *hostname,csprng &RNG,int &favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS);
extern int TLS13_resume(Socket &client,char *hostname,csprng &RNG,int favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS,octet &EARLY);

#endif