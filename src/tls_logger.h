// Log protocol progress
#ifndef TLS_LOGGER_H
#define TLS_LOGGER_H

#include <string.h>
#include "tls1_3.h"
#include "x509.h"

using namespace core;
extern void myprintf(char *s);
extern void logger(char *preamble,char *string,unsign32 info,octet *O);
extern void logServerHello(int cipher_suite,int kex,int pskid,octet *PK,octet *CK);
extern void logTicket(int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octet *NONCE,octet *ETICK);
extern void logCert(octet *CERT);
extern void logCertDetails(char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT);
extern void logServerResponse(int rtn,octet *O);
#endif
