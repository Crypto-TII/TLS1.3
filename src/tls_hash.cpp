// Transcript Hash
// could be SHA256 or SHA384/512 - or in future others
#include "tls_hash.h"

void Hash_Init(int hlen,unihash *h)
{
    if (hlen==32) 
        HASH256_init(&(h->sh32));
    if (hlen==48)
        HASH384_init(&(h->sh64));
    if (hlen==64)
        HASH512_init(&(h->sh64));
    h->hlen=hlen;
}

void Hash_Process(unihash *h,int b)
{
    if (h->hlen==32)
        HASH256_process(&(h->sh32),b);
    if (h->hlen==48)
        HASH384_process(&(h->sh64),b);
    if (h->hlen==64)
        HASH512_process(&(h->sh64),b);
}

void Hash_Output(unihash *h,char *d)
{
    if (h->hlen==32)
        HASH256_continuing_hash(&(h->sh32),d);
    if (h->hlen==48)
        HASH384_continuing_hash(&(h->sh64),d);
    if (h->hlen==64)
        HASH384_continuing_hash(&(h->sh64),d);
}
