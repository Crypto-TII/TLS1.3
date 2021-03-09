// Process output sent to Server
#ifndef TLS_CLIENT_SEND_H
#define TLS_CLIENT_SEND_H

#include "core.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"

using namespace core;

extern void sendCCCS(Socket &client);
extern int addPreSharedKeyExt(octet *EXT,unsign32 age,octet *IDS,int sha);
extern void addServerNameExt(octet *EXT,char *servername);
extern void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups);
extern void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs);
extern void addKeyShareExt(octet *EXT,int alg,octet *PK);
extern void addMFLExt(octet *EXT,int mode);
extern void sendBinder(Socket &client,csprng *RNG,octet *B,octet *BND,octet *IO);
extern void addPSKExt(octet *EXT,int mode);
extern void addVersionExt(octet *EXT,int version);
extern void addPadding(octet *EXT,int n);
extern void addCookieExt(octet *EXT,octet *CK);
extern void addEarlyDataExt(octet *EXT);
extern int clientRandom(octet *RN,csprng *RNG);
extern int sessionID(octet *SI,csprng *RNG);
extern int cipherSuites(octet *CS,int ncs,int *ciphers); 

extern void sendClientMessage(Socket &client,csprng *RNG,int rectype,int version,crypto *send,octet *CM,octet *EXT,octet *IO);
extern void sendClientHello(Socket &client,csprng *RNG,int version,octet *CH,int nsc,int *ciphers,octet *CID,octet *EXTENSIONS,int extra,octet *IO);
extern void sendClientAlert(Socket &client,csprng *RNG,int type,crypto *send,octet *IO);
extern void sendClientVerify(Socket &client,csprng *RNG,crypto *send,unihash *h,octet *CHF,octet *IO);
extern void sendEndOfEarlyData(Socket &client,csprng *RNG,crypto *send,unihash *h,octet *IO);
extern void sendBindersList(Socket &client,csprng *RNG,octet *B,int npsks,octet BNDS[],octet *IO);

extern int alert_from_cause(int rtn);
#endif
