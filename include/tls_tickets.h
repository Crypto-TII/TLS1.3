/**
 * @file tls_tickets.h
 * @author Mike Scott
 * @brief TLS 1.3 process resumption tickets
 *
 */
// Process Resumption Tickets

#ifndef TLS_TICKETS_H
#define TLS_TICKETS_H

#include "tls1_3.h" 
#include "tls_client_recv.h"

/**	@brief read milliseconds from a stop-watch 
 *
	@return milliseconds read from stop-watch
 */
extern unsigned long millis();

/**	@brief parse a received ticket octad into a ticket structure 
 *
	@param TICK the input ticket octad
    @param T the output ticket structure
    @param birth the birth time of the ticket
    @return bad ticket error, or 0 if ticket is good
 */
extern int parseTicket(octad *TICK,unsign32 birth,ticket *T);

/**	@brief initialize a ticket structure
 *
    @param T the ticket structure
 */
extern void initTicketContext(ticket *T);

#endif
