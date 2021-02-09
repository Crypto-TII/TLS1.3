// Process Resumption Tickets

#ifndef TLS_TICKETS_H
#define TLS_TICKETS_H

#include "tls1_3.h" 
#include "tls_client_recv.h"

using namespace core;

extern unsigned long millis();
extern int parseTicket(octet *TICK,ticket *T); 
extern void init_ticket_context(ticket *T,unsign32 birthtime);

#endif
