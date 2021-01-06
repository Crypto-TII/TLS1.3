// extract traffic, handshake and application keys from raw secrets
#ifndef TLS_KEYS_CALC_H
#define TLS_KEYS_CALC_H

#include "core.h"
#include "tls1_3.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "ecdh_C25519.h"


using namespace core;

extern void GET_HANDSHAKE_SECRETS(int sha,octet *HS,octet *CHK,octet *CHIV,octet *SHK,octet *SHIV,octet *CHTS,octet *SHTS, octet *H,octet *SS);
extern void GET_APPLICATION_SECRETS(int sha,octet *CAK,octet *CAIV,octet *SAK,octet *SAIV,octet *CTS,octet *STS,octet *H,octet *HS);
extern unsign32 UPDATE_KEYS(octet *K,octet *IV,octet *TS);
extern bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H);
extern void VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H);
extern void GENERATE_KEY_PAIR(csprng *RNG,int group,octet *SK,octet *PK);
extern void GENERATE_SHARED_SECRET(int group,octet *SK,octet *PK,octet *SS);
extern unsign32 updateIV(octet *NIV,octet *OIV,unsign32 recno);

#endif