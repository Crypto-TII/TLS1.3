// 
// Process Resumption Tickets
//

#include "tls_tickets.h"

// return ticket age in milliseconds
int milliseconds(struct timeval start_time,struct timeval end_time)
{
   long milli_time, seconds, useconds;
   seconds = end_time.tv_sec - start_time.tv_sec; //seconds
   useconds = end_time.tv_usec - start_time.tv_usec; //milliseconds
   milli_time = ((seconds) * 1000 + useconds/1000.0);
   return (int)milli_time;
}

// Initialise a ticket and record its date of birth
void init_ticket_context(ticket *T,struct timeval &birthday)
{
    T->NONCE={0,32,T->nonce};
    T->TICK={0,TLS_MAX_TICKET_SIZE,T->tick};
    T->lifetime=0;
    T->age_obfuscator=0;
    T->max_early_data=0;
    T->birth=birthday;
}

// Parse ticket data into a ticket structure 
int parseTicket(octet *TICK,ticket *T)  
{
    ret r;
    int ext,len,tmplen,ptr=0;
    if (TICK->len==0) return BAD_TICKET;
    r=parseInt32(TICK,ptr);  if (r.err) return BAD_TICKET; T->lifetime=r.val;
    r=parseInt32(TICK,ptr);  if (r.err) return BAD_TICKET; T->age_obfuscator=r.val;
    r=parseByte(TICK,ptr); len=r.val;  if (r.err) return BAD_TICKET;

    r=parseOctet(&T->NONCE,len,TICK,ptr);  if (r.err) return BAD_TICKET;
    r=parseInt16(TICK,ptr); len=r.val; if (r.err) return BAD_TICKET;
    r=parseOctet(&T->TICK,len,TICK,ptr);  if (r.err) return BAD_TICKET; // extract ticket
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
