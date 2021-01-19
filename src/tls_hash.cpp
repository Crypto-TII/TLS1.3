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

// Add to transcript hash 
void running_hash(octet *O,unihash *h)
{
    for (int i=0;i<O->len;i++)
        Hash_Process(h,O->val[i]);
}

// Output transcript hash 
void transcript_hash(unihash *h,octet *O)
{
    Hash_Output(h,O->val); O->len=h->hlen; 
}

// special case handling for first clientHello after retry request
void running_syn_hash(octet *O,unihash *h)
{
    int sha=h->hlen;
    unihash rhash;
    char hh[TLS_MAX_HASH];
    octet HH={0,sizeof(hh),hh};

    Hash_Init(sha,&rhash); 
 // RFC 8446 - "special synthetic message"
    running_hash(O,&rhash);
    transcript_hash(&rhash,&HH);
    
    Hash_Process(h,MESSAGE_HASH);
    Hash_Process(h,0); Hash_Process(h,0);
    Hash_Process(h,sha);   // fe 00 00 sha
    
    running_hash(&HH,h);
}


