// TLS Server Cert Verify Code
#ifndef TLS_SCV_H
#define TLS_SCV_H
#include "tls1_3.h" 
#include "tls_parse_octet.h"
#include "core.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h" 
#include "rsa_RSA2048.h"
#include "rsa_RSA4096.h"

using namespace core;

extern bool IS_SERVER_CERT_VERIFY(int sigalg,octet *SCVSIG,octet *H,octet *CERTPK);

#endif
