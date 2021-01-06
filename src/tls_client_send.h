// Process input recieved from Server
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

extern void addPresharedKeyExt(octet *EXT,octet *TICK,unsign32 obf_age,octet* BD);
extern void addServerNameExt(octet *EXT,char *servername);
extern void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups);
extern void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs);
extern void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[]);
extern void addPSKExt(octet *EXT,int mode);
extern void addVersionExt(octet *EXT,int version);
extern void addCookieExt(octet *EXT,octet *CK);
extern int clientRandom(octet *RN,csprng *RNG);
extern int sessionID(octet *SI,csprng *RNG);
extern int cipherSuites(octet *CS,int ncs,int *ciphers); 

extern void sendClientMessage(int sock,int rectype,int version,octet *K,octet *OIV,unsign32 &recno,octet *CM);
extern void sendClientHello(int sock,int version,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS);
extern void sendClientAlert(int sock,int type,octet *K,octet *OIV,unsign32 &recno);
extern void sendClientVerify(int sock,octet *K,octet *OIV,unsign32 &recno,octet *CHF);

#endif
