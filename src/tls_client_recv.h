// Process input recieved from Server
#ifndef TLS_CLIENT_RECV_H
#define TLS_CLIENT_RECV_H

#include <string.h>
#include "core.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"

using namespace core;
extern ret parseOctet(octet *E,int len,octet *M,int &ptr);
extern ret parseInt16(octet *M,int &ptr);
extern ret parseInt24(octet *M,int &ptr);
extern ret parseInt32(octet *M,int &ptr);
extern ret parseByte(octet *M,int &ptr);

extern int getServerFragment(int sock,crypto *recv,octet *SR);
extern ret parseByteorPull(int sock,octet *SR,int &ptr,crypto *recv);
extern ret parseInt32orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern ret parseInt24orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern ret parseInt16orPull(int sock,octet *SR,int &ptr,crypto *recv);
extern ret parseOctetorPull(int sock,octet *O,int len,octet *SR,int &ptr,crypto *recv);
extern int getServerEncryptedExtensions(int sock,octet *SR,crypto *recv,unihash *trans_hash,bool &early_data_accepted);
extern int getServerCertificateChain(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *CERTCHAIN);
extern int getServerCertVerify(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *SCVSIG,int &sigalg);
extern int getServerFinished(int sock,octet *SR,crypto *recv,unihash *trans_hash,octet *HFIN);
extern int getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK,int &pskid);

#endif