// 
// Process Resumption Tickets
//

#include "tls_tickets.h"

// read milliseconds from a stop-watch
// (Arduino has a built in function with the same name)
#ifndef TLS_ARDUINO
#include <sys/time.h>

unsigned long millis()
{
    unsigned long milli_time, seconds, useconds;
    struct timeval stop_watch;
    gettimeofday(&stop_watch, NULL);
    seconds=stop_watch.tv_sec;
    useconds=stop_watch.tv_usec;
    milli_time=((seconds) * 1000 + useconds/1000);
    return milli_time;
}
#endif

// Initialise a ticket and record its date of birth
void init_ticket_context(ticket *T,unsign32 birthtime)
{
    T->NONCE.len = 0;
    T->NONCE.max = 32;
    T->NONCE.val = T->nonce;

    T->TICK.len = 0;
    T->TICK.max = TLS_MAX_TICKET_SIZE;
    T->TICK.val = T->tick;

    T->lifetime=0;
    T->age_obfuscator=0;
    T->max_early_data=0;
    T->birth=birthtime;
}

// Parse ticket data into a ticket structure 
int parseTicket(octad *TICK,ticket *T)  
{
    ret r;
    int ext,len,tmplen,ptr=0;
    if (TICK->len==0) return BAD_TICKET;
    r=parseInt32(TICK,ptr);  if (r.err) return BAD_TICKET; T->lifetime=r.val;
    r=parseInt32(TICK,ptr);  if (r.err) return BAD_TICKET; T->age_obfuscator=r.val;
    r=parseByte(TICK,ptr); len=r.val;  if (r.err) return BAD_TICKET;

    r=parseoctad(&T->NONCE,len,TICK,ptr);  if (r.err) return BAD_TICKET;
    r=parseInt16(TICK,ptr); len=r.val; if (r.err) return BAD_TICKET;
    r=parseoctad(&T->TICK,len,TICK,ptr);  if (r.err) return BAD_TICKET; // extract ticket
    r=parseInt16(TICK,ptr); len=r.val; if (r.err) return BAD_TICKET;    // length of extensions

    T->max_early_data=0;
    while (len>0)
    {
        r=parseInt16(TICK,ptr); ext=r.val; if (r.err) return BAD_TICKET;
        len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            {
                r=parseInt16(TICK,ptr); tmplen=r.val; if (tmplen!=4 || r.err) return BAD_TICKET;
                len-=2;  // tmplen=4 - max_early data
                r=parseInt32(TICK,ptr); T->max_early_data=r.val;
                len-=tmplen;
                break;
            }
       default :   // ignore other extensions  
            r=parseInt16(TICK,ptr); tmplen=r.val;
            len-=2;
            len-=tmplen; ptr+=tmplen;
            break;
        }
        if (r.err) return BAD_TICKET;
    }
    return 0;
}
