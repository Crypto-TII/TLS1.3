/**
 * @file tls_logger.h
 * @author Mike Scott
 * @brief TLS 1.3 logging
 *
 */
// Log protocol progress
#ifndef TLS_LOGGER_H
#define TLS_LOGGER_H

#include <string.h>
#include "tls1_3.h"
#include "tls_x509.h"

/**	@brief internal printf function - all output funnels through this function 
 *
	@param s a string to be output
 */
extern void myprintf(char *s);

/**	@brief basic logging function
 *
	@param preamble a string to be output
    @param string another string, or a format specifier for info, or NULL
    @param info an integer to be output
    @param O an octad to be output (or NULL)
 */
extern void logger(char *preamble,char *string,unsign32 info,octad *O);

/**	@brief logging the Server hello
 *
	@param cipher_suite the chosen cipher suite
    @param kex the chosen key exchange algorithm
    @param pskid the chosen preshared key (or -1 if none)
    @param PK the Server Public Key
    @param CK a Cookie (if any)
 */
extern void logServerHello(int cipher_suite,int kex,int pskid,octad *PK,octad *CK);

/**	@brief logging a resumption ticket
 *
	@param T a resumption ticket
 */
extern void logTicket(ticket *T);

/**	@brief logging server extended extensions responses vs expectations
 *
	@param e structure containing server expectations
	@param r structure containing server responses
 */
extern void logEncExt(ee_status *e,ee_status *r);

/**	@brief logging a Certificate in standard base 64 format
 *
	@param CERT the certificate to be logged
 */
extern void logCert(octad *CERT);

/**	@brief logging Certificate details
 *
	@param txt preamble text
    @param PUBKEY the certificate public key octad
    @param pk the public key type
    @param SIG the signature on the certificate
    @param sg the signature type
    @param ISSUER the (composite) certificate issuer
    @param SUBJECT the (composite) certificate subject
 */
extern void logCertDetails(char *txt,octad *PUBKEY,pktype pk,octad *SIG,pktype sg,octad *ISSUER,octad *SUBJECT);

/**	@brief log client processing of a Server response
 *
	@param r the Server response 
 */
extern void logServerResponse(ret r);

/**	@brief log Server Alert
 *
    @param detail the server's alert code
 */
extern void logAlert(int detail);


/**	@brief name Cipher Suite
 *
    @param cipher_suite print Cipher Suite
 */
extern void nameCipherSuite(int cipher_suite);


/**	@brief log Cipher Suite
 *
    @param cipher_suite the Cipher Suite to be logged
 */
extern void logCipherSuite(int cipher_suite);

/**	@brief name Key Exchange Group
 *
    @param kex print key exchange algorithm
 */
extern void nameKeyExchange(int kex);

/**	@brief log Key Exchange Group
 *
    @param kex the Key Exchange Group to be logged
 */
extern void logKeyExchange(int kex);

/**	@brief name Signature Algorithm
 *
    @param sigAlg print Signature Algorithm
 */
extern void nameSigAlg(int sigAlg);

/**	@brief log Signature Algorithm
 *
    @param sigAlg the Signature Algorithm to be logged
 */
extern void logSigAlg(int sigAlg);

#endif
