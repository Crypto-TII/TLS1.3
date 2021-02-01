// Process output sent to Server
#ifndef TLS_CLIENT_SEND_H
#define TLS_CLIENT_SEND_H

#include <string.h>
#include "core.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"

using namespace core;

extern void sendCCCS(Socket &client);
extern int addPreSharedKeyExt(octet *EXT,int npsks,unsign32 age[],octet IDS[],int sha);
extern void addServerNameExt(octet *EXT,char *servername);
extern void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups);
extern void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs);
extern void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[]);
extern void addMFLExt(octet *EXT,int mode);

extern void sendBindersList(Socket &client,octet *B,int npsks,octet BNDS[]);
extern void addPSKExt(octet *EXT,int mode);
extern void addVersionExt(octet *EXT,int version);
extern void addCookieExt(octet *EXT,octet *CK);
extern void addEarlyDataExt(octet *EXT);
extern int clientRandom(octet *RN,csprng *RNG);
extern int sessionID(octet *SI,csprng *RNG);
extern int cipherSuites(octet *CS,int ncs,int *ciphers); 

extern void sendClientMessage(Socket &client,int rectype,int version,crypto *send,octet *CM,octet *IO);
extern void sendClientHello(Socket &client,int version,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS,int extra,octet *IO);
extern void sendClientAlert(Socket &client,int type,crypto *send,octet *IO);
extern void sendClientVerify(Socket &client,crypto *send,unihash *h,octet *CHF,octet *IO);
extern void sendEndOfEarlyData(Socket &client,crypto *send,unihash *h,octet *IO);
extern void sendBindersList(Socket &client,octet *B,int npsks,octet BNDS[],octet *IO);

extern int alert_from_cause(int rtn);
#endif
