// Process input received from Server
#ifndef TLS_LOGGER_H
#define TLS_LOGGER_H

#include <string.h>
#include "tls1_3.h"
#include "x509.h"

using namespace core;

extern void logger(FILE *fp,char *preamble,char *string,unsign32 info,octet *O);
extern void logServerHello(FILE *fp,int cipher_suite,int kex,int pskid,octet *PK,octet *CK);
extern void logTicket(FILE *fp,int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octet *NONCE,octet *ETICK);
extern void logCert(FILE *fp,octet *CERT);
extern void logCertDetails(FILE *fp,char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT);
extern void logServerResponse(FILE *fp,int rtn,octet *O);
#endif
