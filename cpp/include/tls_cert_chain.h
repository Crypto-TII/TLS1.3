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
	@param cert_type the certificate type (a certificate or a raw key)
    @param PUBKEY the Server's public key extracted from the Certificate chain 
    @param SIG signature (supplied as workspace)
	@return 0 if certificate chain is OK, else returns negative failure reason
 */
extern int checkServerCertChain(octad *CERTCHAIN,char *hostname,int cert_type,octad *PUBKEY,octad *SIG);  

/**	@brief Get Client private key and Certificate chain from .pem files
 *
    @param PRIVKEY the Client's private  key
	@param cert_type the certificate type (a certificate or a raw key)
    @param CERTCHAIN the Client's certificate chain
	@return type of private key, ECC or RSA
 */
extern int getClientPrivateKeyandCertChain(octad *PRIVKEY,int cert_type,octad *CERTCHAIN);

#endif
