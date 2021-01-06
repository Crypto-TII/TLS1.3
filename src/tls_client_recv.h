// Process input recieved from Server
#ifndef TLS_CLIENT_RECV_H
#define TLS_CLIENT_RECV_H

#include <string.h>
#include "core.h"
#include "tls1_3.h"
#include "tls_hash.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"
#include "tls_parse_octet.h"

using namespace core;

extern int getServerFragment(int sock,octet *SHK,octet *SHIV,unsign32 &recno,octet *SR);
extern int parseByteorPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno);
extern unsigned int parseInt32orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno);
extern int parseInt24orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno);
extern int parseInt16orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno);
extern int parseOctetorPull(int sock,octet *O,int len,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno);
extern bool getServerEncryptedExtensions(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *SEXT);
extern bool getServerCertificateChain(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *CERTCHAIN);
extern int getServerCertVerify(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *SCVSIG);
extern bool getServerFinished(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *HFIN);
extern int getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK);

#endif