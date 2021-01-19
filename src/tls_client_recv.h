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

extern int getServerFragment(int sock,crypto *recv,octet *SR);
extern int parseByteorPull(int sock,octet *SR,int &ptr,crypto *recv);
extern unsigned int parseInt32orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern int parseInt24orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern int parseInt16orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern int parseOctetorPull(int sock,octet *O,int len,octet *SR,int &ptr,crypto *recv);
extern bool getServerEncryptedExtensions(int sock,octet *SR,crypto *recv,unihash *trans_hash,bool &early_data_accepted);
extern bool getServerCertificateChain(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *CERTCHAIN);
extern int getServerCertVerify(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *SCVSIG);
extern bool getServerFinished(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *HFIN);
extern int getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK,int &pskid);

#endif