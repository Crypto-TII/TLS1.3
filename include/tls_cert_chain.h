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
#include "tls_x509.h"
#include "tls_sal.h"
#include "tls_client_recv.h"
#include "tls_logger.h"
#include "tls_certs.h"

using namespace std;

/**	@brief Check Certificate Chain for hostname, and extract public key
 *
	@param CERTCHAIN the input certificate chain
    @param hostname the input Server name associated with the Certificate chain
    @param PUBKEY the Server's public key extracted from the Certificate chain 
	@return 0 if certificate chain is OK, else returns negative failure reason
 */
extern int checkServerCertChain(octad *CERTCHAIN,char *hostname,octad *PUBKEY);  

/**	@brief Get Client private key and Certificate chain from .pem files
 *
    @param nccsalgs the number of acceptable signature algorithms
    @param csigAlgs acceptable signature algorithms
    @param PRIVKEY the Client's private  key
    @param CERTCHAIN the Client's certificate chain
	@return type of private key, ECC or RSA
 */
extern int getClientPrivateKeyandCertChain(int nccsalgs,int *csigAlgs,octad *PRIVKEY,octad *CERTCHAIN);

#endif
