// TLS Server Certchain Code
#ifndef TLS_CERT_CHAIN_H
#define TLS_CERT_CHAIN_H
#include "tls1_3.h" 
#include "core.h"
#include "x509.h"
#include "ecdh_NIST256.h"  
#include "rsa_RSA2048.h"
#include "rsa_RSA4096.h"
#include <fstream>

using namespace core;
using namespace std;

extern void SHOW_CERT_DETAILS(char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT);

extern pktype GET_CERT_DETAILS(octet *SCERT,octet *CERT,octet *SIG,octet *ISSUER,octet *SUBJECT);
extern pktype GET_PUBLIC_KEY_FROM_SIGNED_CERT(octet *SCERT,octet *PUBLIC_KEY);

//extern void GET_CERT_DETAILS(octet *CERTIFICATE,octet *CERT,octet *PUBKEY,pktype *pk,octet *SIG,pktype *sg,octet *ISSUER,octet *SUBJECT);
extern bool CHECK_CERT_CHAIN(octet *CERTCHAIN,octet *PUBKEY);
extern bool CHECK_CERT_SIG(pktype st,octet *CERT,octet *SIG, octet *PUBKEY);
extern void OUTPUT_CERT(octet *CERT);
extern bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY);

#endif
