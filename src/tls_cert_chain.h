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

extern bool CHECK_CERT_CHAIN(FILE *fp,octet *CERTCHAIN,octet *PUBKEY);
extern bool IS_SERVER_CERT_VERIFY(FILE *fp,int sigalg,octet *SCVSIG,octet *H,octet *CERTPK);

#endif
