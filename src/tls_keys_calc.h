// extract traffic, handshake and application keys from raw secrets
#ifndef TLS_KEYS_CALC_H
#define TLS_KEYS_CALC_H

#include "core.h"
#include "tls1_3.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "ecdh_C25519.h"


using namespace core;

extern void init_crypto_context(crypto *C);
extern void create_crypto_context(crypto *C,octet *K,octet *IV);
extern void increment_crypto_context(crypto *C);
extern void init_crypto(crypto *C,octet *K,octet *IV);
extern void GET_KEY_AND_IV(int cipher_suite,octet *TS,crypto *context);
extern void RECOVER_PSK(int sha,octet *RMS,octet *NONCE,octet *PSK);
extern void GET_EARLY_SECRET(int sha,octet *PSK,octet *ES,octet *BKE,octet *BKR);
extern void GET_LATER_SECRETS(int sha,octet *H,octet *ES,octet *CETS,octet *EEMS);
//extern void GET_EARLY_SECRETS(int cipher_suite,octet *PSK,octet *ES,octet *BKE,octet *BKR,octet *CETS,octet *EEMS,octet *H);
extern void GET_HANDSHAKE_SECRETS(int sha,octet *SS,octet *PSK, octet *H,octet *HS,octet *CHTS,octet *SHTS);
extern void GET_APPLICATION_SECRETS(int sha,octet *HS,octet *SFH,octet *CFH,octet *CTS,octet *STS,octet *EMS,octet *RMS);
extern unsign32 UPDATE_KEYS(crypto *context,octet *TS);
extern bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H);
extern void VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H);
extern void GENERATE_KEY_PAIR(csprng *RNG,int group,octet *SK,octet *PK);
extern void GENERATE_SHARED_SECRET(int group,octet *SK,octet *PK,octet *SS);
extern unsign32 updateIV(octet *NIV,octet *OIV,unsign32 recno);

#endif