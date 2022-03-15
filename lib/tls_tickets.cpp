// 
// Process Resumption Tickets and external PSKs
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

// Initialise a ticket. Also record the cipher-suite in use, and servers favourite key exchange group
void initTicketContext(ticket *T)
{
    T->valid=false;

    T->NONCE.len = 0;
    T->NONCE.max = TLS_MAX_KEY;
    T->NONCE.val = T->nonce;

    T->PSK.len = 0;
    T->PSK.max = TLS_MAX_HASH;
    T->PSK.val = T->psk;

    T->TICK.len = 0;
    T->TICK.max = TLS_MAX_TICKET_SIZE;
    T->TICK.val = T->tick;

    T->lifetime=0;
    T->age_obfuscator=0;
    T->max_early_data=0;
    T->birth=0;
    T->cipher_suite=0;
    T->favourite_group=0;
    T->origin=0;
}

void endTicketContext(ticket *T)
{
    OCT_kill(&T->NONCE);
    OCT_kill(&T->PSK);
    OCT_kill(&T->TICK);

    T->lifetime=0;
    T->age_obfuscator=0;
    T->max_early_data=0;
    T->birth=0;
    T->cipher_suite=0;
    T->favourite_group=0;
    T->origin=0;
}

// Parse ticket data and birth time into a ticket structure 
int parseTicket(octad *TICK,unsign32 birth,ticket *T)  
{
    ret r;
    int ext,len,tmplen,ptr=0;
    if (TICK->len==0) return BAD_TICKET;
    r=parseInt(TICK,4,ptr);  if (r.err) return BAD_TICKET; T->lifetime=r.val;
    r=parseInt(TICK,4,ptr);  if (r.err) return BAD_TICKET; T->age_obfuscator=r.val;
    r=parseInt(TICK,1,ptr); len=r.val;  if (r.err) return BAD_TICKET;

    r=parseoctad(&T->NONCE,len,TICK,ptr);  if (r.err) return BAD_TICKET;
    r=parseInt(TICK,2,ptr); len=r.val; if (r.err) return BAD_TICKET;
    r=parseoctad(&T->TICK,len,TICK,ptr);  if (r.err) return BAD_TICKET; // extract ticket
    r=parseInt(TICK,2,ptr); len=r.val; if (r.err) return BAD_TICKET;    // length of extensions

    T->birth=birth;
    T->max_early_data=0;
    while (len>0)
    {
        r=parseInt(TICK,2,ptr); ext=r.val; if (r.err) return BAD_TICKET;
        len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            {
                r=parseInt(TICK,2,ptr); tmplen=r.val; if (tmplen!=4 || r.err) return BAD_TICKET;
                len-=2;  // tmplen=4 - max_early data
                r=parseInt(TICK,4,ptr); T->max_early_data=r.val;
                len-=tmplen;
                break;
            }
       default :   // ignore other extensions  
            r=parseInt(TICK,2,ptr); tmplen=r.val;
            len-=2;
            len-=tmplen; ptr+=tmplen;
            break;
        }
        if (r.err) return BAD_TICKET;
    }
    T->valid=true;
    return 0;
}

// check a ticket exists, its good, and its not out-of-date
bool ticket_still_good(ticket *T)
{
    unsign32 time_ticket_received,time_ticket_used;
    unsign32 age;
    if (T->lifetime<=0 || !T->valid)
        return false;
    time_ticket_received=T->birth;
    time_ticket_used=(unsign32)millis();
    age=time_ticket_used-time_ticket_received;
    if (age>1000*T->lifetime)
        return false;
    return true;
}
