// TLS SHA2 hashing
#ifndef TLS_HASH_H
#define TLS_HASH_H
#include "core.h"

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

#endif