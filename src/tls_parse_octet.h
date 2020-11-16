// TLS parse octets
#ifndef TLS_PARSE_OCTET_H
#define TLS_PARSE_OCTET_H
#include "core.h"

using namespace core;

extern int parseOctet(octet *E,int len,octet *M,int &ptr);
extern int parseInt16(octet *M,int &ptr);
extern int parseInt24(octet *M,int &ptr);
extern int parseByte(octet *M,int &ptr);

#endif