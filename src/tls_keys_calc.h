// extract traffic, handshake and application keys from raw secrets
#ifndef TLS_KEYS_CALC_H
#define TLS_KEYS_CALC_H

#include "core.h"
#include "tls1_3.h"

using namespace core;

extern void GET_HANDSHAKE_SECRETS(int sha,octet *HS,octet *CHK,octet *CHIV,octet *SHK,octet *SHIV,octet *CHTS,octet *SHTS, octet *H,octet *SS);
extern void GET_APPLICATION_SECRETS(int sha,octet *CAK,octet *CAIV,octet *SAK,octet *SAIV,octet *H,octet *HS);
extern bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H);


#endif