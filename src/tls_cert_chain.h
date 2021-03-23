/**
 * @file tls_cert_chain.h
 * @author Mike Scott
 * @brief Process Certificate Chain
 *
 */

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

using namespace core;
using namespace std;

/**	@brief Check Certificate Chain
 *
	@param CERTCHAIN the input certificate chain
    @param hostname the input Server name associated with the Certificate chain
    @param PUBKEY the Server's public key extracted from the Certificate chain 
	@return true if certificate chain is OK, else returns false
 */
extern bool CHECK_CERT_CHAIN(octet *CERTCHAIN,char *hostname,octet *PUBKEY);  

/**	@brief verify Server's signature on protocol transcript
 *
	@param sigalg the algorithm used for digital signature
    @param SCVSIG the input signature on the transcript
    @param H the transcript hash 
    @param CERTPK the Server's public key
	@return true if signature is verified, else returns false
 */
extern bool IS_SERVER_CERT_VERIFY(int sigalg,octet *SCVSIG,octet *H,octet *CERTPK);

#endif
