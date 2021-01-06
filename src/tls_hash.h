// TLS SHA2 hashing
#ifndef TLS_HASH_H
#define TLS_HASH_H
#include "core.h"
#include "tls1_3.h"

using namespace core;

typedef struct 
{
    hash256 sh32;
    hash512 sh64;
    int hlen;
} unihash;

extern void Hash_Init(int hlen,unihash *h);
extern void Hash_Process(unihash *h,int b);
extern void Hash_Output(unihash *h,char *d);

extern void running_hash(unihash *h,octet *O);
extern void transcript_hash(octet *O,unihash *h);
extern void running_syn_hash(unihash *h,octet *O);
#endif