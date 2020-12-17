// TLS utility parsing functions

#include "tls_parse_octet.h"

// parse out an octet of length len from octet M into E
int parseOctet(octet *E,int len,octet *M,int &ptr)
{
    if (ptr+len>M->len) return -1;
    if (len>E->max) return -1;
    E->len=len;
    for (int i=0;i<len;i++ )
        E->val[i]=M->val[ptr++];
    return len;
}

// parse out a 16-bit integer from octet M
int parseInt16(octet *M,int &ptr)
{
    int b0,b1;
    if (ptr+2>M->len) return -1;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    return 256*b0+b1;
}

// parse out a 24-bit integer from octet M
int parseInt24(octet *M,int &ptr)
{
    int b0,b1,b2;
    if (ptr+3>M->len) return -1;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    b2=(int)(unsigned char)M->val[ptr++];
    return 65536*b0+256*b1+b2;
}

// parse out a 32-bit integer from octet M
unsigned int parseInt32(octet *M,int &ptr)
{
    unsigned int b0,b1,b2,b3;
    if (ptr+4>M->len) return -1;
    b0=(unsigned int)(unsigned char)M->val[ptr++];
    b1=(unsigned int)(unsigned char)M->val[ptr++];
    b2=(unsigned int)(unsigned char)M->val[ptr++];
    b3=(unsigned int)(unsigned char)M->val[ptr++];
    return 16777216*b0+65536*b1+256*b2+b3;
}

// parse out a byte from octet M
int parseByte(octet *M,int &ptr)
{
    if (ptr+1>M->len) return -1;
    return (int)(unsigned char)M->val[ptr++];
}
