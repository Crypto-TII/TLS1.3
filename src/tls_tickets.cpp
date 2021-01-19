// 
// Process Resumption Tickets
//

#include "tls_tickets.h"

int milliseconds(struct timeval start_time,struct timeval end_time)
{
   long milli_time, seconds, useconds;
   seconds = end_time.tv_sec - start_time.tv_sec; //seconds
   useconds = end_time.tv_usec - start_time.tv_usec; //milliseconds
   milli_time = ((seconds) * 1000 + useconds/1000.0);
   return (int)milli_time;
}

// parse out ticket contents. Note that ETICK is the actual ticket to be passed back in a Pre-Shared-Key Extension
int parseTicket(octet *TICK,octet *NONCE,octet *ETICK,unsign32& obfuscated_age,unsign32& max_early_data)
{
    int tmplen,ptr=0;
    int lifetime=parseInt32(TICK,ptr);
    obfuscated_age=parseInt32(TICK,ptr);
    int len=parseByte(TICK,ptr);
    parseOctet(NONCE,len,TICK,ptr);
    len=parseInt16(TICK,ptr);
    parseOctet(ETICK,len,TICK,ptr); // extract ticket
    len=parseInt16(TICK,ptr);   // length of extensions
    max_early_data=0;
    while (len>0)
    {
        int ext=parseInt16(TICK,ptr); len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            {
                max_early_data=parseInt32(TICK,ptr);
                len-=4;
                break;
            }
       default :    
            tmplen=parseInt16(TICK,ptr); len-=2;
            len-=tmplen;
            break;
        }
    }
    return lifetime;
}