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
#include "tls_cacerts.h"

// Standard Hash Types

#define TLS_SHA256 32           /**< SHA256 hash length in bytes */
#define TLS_SHA384 48           /**< SHA384 hash length in bytes */
#define TLS_SHA512 64           /**< SHA512 hash length in bytes */


using namespace std;

/**	@brief Check Certificate Chain
 *
	@param CERTCHAIN the input certificate chain
    @param hostname the input Server name associated with the Certificate chain
    @param PUBKEY the Server's public key extracted from the Certificate chain 
	@return 0 if certificate chain is OK, else returns negative failure reason
 */
extern int CHECK_CERT_CHAIN(octad *CERTCHAIN,char *hostname,octad *PUBKEY);  

/**	@brief verify Server's signature on protocol transcript
 *
	@param sigalg the algorithm used for digital signature
    @param SCVSIG the input signature on the transcript
    @param H the transcript hash 
    @param CERTPK the Server's public key
	@return true if signature is verified, else returns false
 */
extern bool IS_SERVER_CERT_VERIFY(int sigalg,octad *SCVSIG,octad *H,octad *CERTPK);

/**	@brief Get Client private key and Certificate chain from .pem files
 *
    @param nccsalgs the number of acceptable signature algorithms
    @param csigAlgs acceptable signature algorithms
    @param PRIVKEY the Client's private  key
    @param CERTCHAIN the Client's certificate chain
	@return type of private key, ECC or RSA
 */
extern int GET_CLIENT_KEY_AND_CERTCHAIN(int nccsalgs,int *csigAlgs,octad *PRIVKEY,octad *CERTCHAIN);

/**	@brief Create Cert Verify message, as a digital signature on some TLS1.3 specific message+transcript hash
 *
    @param sigAlg the signature algorithm
    @param H a transcript hash to be signed
    @param KEY the Client's private key
    @param CCVSIG the output digital signature
 */
extern void CREATE_CLIENT_CERT_VERIFIER(int sigAlg,octad *H,octad *KEY,octad *CCVSIG);

#endif
