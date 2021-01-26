// parse tickets and handle life time

#ifndef TLS_TICKETS_H
#define TLS_TICKETS_H

#include <sys/time.h>
#include <unistd.h>
#include "tls1_3.h" 
#include "tls_client_recv.h"

using namespace core;

extern int milliseconds(struct timeval start_time,struct timeval end_time);
extern int parseTicket(octet *TICK,ticket *T); // octet *NONCE,octet *ETICK,unsign32& obfuscated_age,unsign32& max_early_data);
extern void init_ticket_context(ticket *T,struct timeval &birthday);

#endif
