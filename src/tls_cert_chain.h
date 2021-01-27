// TLS1.3 Server Certificate Chain Code

#ifndef TLS_CERT_CHAIN_H
#define TLS_CERT_CHAIN_H
#include "tls1_3.h" 
#include "core.h"
#include "x509.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "rsa_RSA2048.h"
#include "rsa_RSA4096.h"
#include <fstream>

using namespace core;
using namespace std;

extern pktype GET_CERT_DETAILS(octet *SCERT,octet *CERT,octet *SIG,octet *ISSUER,octet *SUBJECT);
extern pktype GET_PUBLIC_KEY_FROM_SIGNED_CERT(octet *SCERT,octet *PUBLIC_KEY);
extern bool CHECK_CERT_CHAIN(FILE *fp,octet *CERTCHAIN,octet *PUBKEY);
extern bool CHECK_CERT_SIG(FILE *fp,pktype st,octet *CERT,octet *SIG, octet *PUBKEY);
extern bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY);
extern bool IS_SERVER_CERT_VERIFY(FILE *fp,int sigalg,octet *SCVSIG,octet *H,octet *CERTPK);

#endif
