// Process input received from Server

#ifndef TLS_CLIENT_RECV_H
#define TLS_CLIENT_RECV_H

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
extern ret parseOctetptr(octet *E,int len,octet *M,int &ptr);

extern int getServerFragment(Socket &client,crypto *recv,octet *IO);
extern ret parseByteorPull(Socket &client,octet *IO,int &ptr,crypto *recv);
extern ret parseInt32orPull(Socket &client,octet *IO,int &ptr,crypto *recv);
extern ret parseInt24orPull(Socket &client,octet *IO,int &ptr,crypto *recv);
extern ret parseInt16orPull(Socket &client,octet *IO,int &ptr,crypto *recv);
extern ret parseOctetorPull(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv);
extern ret parseOctetorPullptr(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv);

extern int getServerEncryptedExtensions(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,bool &early_data_accepted);
extern int getServerCertVerify(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *SCVSIG,int &sigalg);
extern int getServerFinished(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *HFIN);
extern int getServerHello(Socket &client,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK,int &pskid);
extern int getCheckServerCertificateChain(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,char *hostname,octet *PUBKEY);

#endif