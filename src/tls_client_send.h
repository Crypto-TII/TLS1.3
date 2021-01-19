// Process input received from Server
#ifndef TLS_CLIENT_SEND_H
#define TLS_CLIENT_SEND_H

#include <string.h>
#include "core.h"
#include "tls1_3.h"
#include "tls_hash.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"
#include "tls_parse_octet.h"

using namespace core;

extern int addPreSharedKeyExt(octet *EXT,int npsks,unsign32 age[],octet IDS[],int sha);
extern void addServerNameExt(octet *EXT,char *servername);
extern void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups);
extern void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs);
extern void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[]);
extern void sendBindersList(int sock,octet *B,int npsks,octet BNDS[]);
extern void addPSKExt(octet *EXT,int mode);
extern void addVersionExt(octet *EXT,int version);
extern void addCookieExt(octet *EXT,octet *CK);
extern void addEarlyDataExt(octet *EXT);
extern int clientRandom(octet *RN,csprng *RNG);
extern int sessionID(octet *SI,csprng *RNG);
extern int cipherSuites(octet *CS,int ncs,int *ciphers); 

extern void sendClientMessage(int sock,int rectype,int version,crypto *send,octet *CM);
extern void sendClientHello(int sock,int version,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS,int extra);
extern void sendClientAlert(int sock,int type,crypto *send);
extern void sendClientVerify(int sock,crypto *send,unihash *h,octet *CHF);
extern void sendEndOfEarlyData(int sock,crypto *send,unihash *h);

#endif
