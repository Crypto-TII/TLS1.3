/**
 * @file tls_client_send.h
 * @author Mike Scott
 * @brief Process Output to be sent to the Server
 *
 */

// Process output sent to Server
#ifndef TLS_CLIENT_SEND_H
#define TLS_CLIENT_SEND_H

#include "tls_sal.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"

/**	@brief Send Change Cipher Suite message 
 *
    @param session the TLS session structure
 */
extern void sendCCCS(TLS_session *session);

/**	@brief Add PreShared Key extension to under-construction Extensions Octet (omitting binder)
 *
	@param EXT the extensions octad which is being built
    @param age the obfuscated age of the preshared key
    @param IDS the proposed preshared key identity
    @param sha the hash algorithm used to calculate the HMAC binder
    @return length of binder to be sent later
 */
extern int addPreSharedKeyExt(octad *EXT,unsign32 age,octad *IDS,int sha);

/**	@brief Add Server name extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param servername the Host name (URL) of the Server
 */          
extern void addServerNameExt(octad *EXT,char *servername);

/**	@brief Add Supported Groups extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param nsg Number of supported groups
    @param supportedGroups an array of supported groups
 */    
extern void addSupportedGroupsExt(octad *EXT,int nsg,int *supportedGroups);


/**	@brief Add Supported TLS1.3 Signature algorithms to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param nsa Number of supported signature algorithms
    @param sigAlgs an array of supported signature algorithms
 */    
extern void addSigAlgsExt(octad *EXT,int nsa,int *sigAlgs);

/**	@brief Add Supported X.509 Certificate Signature algorithms to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param nsac Number of supported signature algorithms
    @param sigAlgsCert an array of supported signature algorithms
 */    
extern void addSigAlgsCertExt(octad *EXT,int nsac,int *sigAlgsCert);


/**	@brief Add Key Share extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param alg the suggested key exchange algorithm
    @param PK the key exchange public value to be sent to the Server
 */  
extern void addKeyShareExt(octad *EXT,int alg,octad *PK);


/**	@brief Add Application Layer Protocol Negotiation (ALPN) extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param AP the IANA sequence associated with the expected protocol
 */ 
extern void addALPNExt(octad *EXT,octad *AP);


/**	@brief Add Maximum Fragment Length extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param mode the proposed maximum fragment size
 */  
extern void addMFLExt(octad *EXT,int mode);

/**	@brief Add Record Size Limit extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param size the demanded maximum fragment size
 */  
extern void addRSLExt(octad *EXT,int size);

/**	@brief Add Preshared Key exchange modes extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param mode the proposed preshared key mode 
 */  
extern void addPSKModesExt(octad *EXT,int mode);

/**	@brief Add Version extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param version the supported TLS version 
 */ 
extern void addVersionExt(octad *EXT,int version);

/**	@brief Add padding extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param n the zero padding length
 */
extern void addPadding(octad *EXT,int n);

/**	@brief Add Cookie extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param CK the cookie octad to be added
 */
extern void addCookieExt(octad *EXT,octad *CK);

/**	@brief Indicate desire to send Early Data in under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
 */
extern void addEarlyDataExt(octad *EXT);

/**	@brief indicate willingness to do post handshake authentication
 *
	@param EXT the extensions octad which is being built
 */
extern void addPostHSAuth(octad *EXT);

/**	@brief Generate 32-byte random octad
 *
	@param RN the output 32-byte octad 
    @return length of output octad
 */
extern int clientRandom(octad *RN);

/**	@brief Build a cipher-suites octad from supported ciphers
 *
	@param CS the output cipher-suite octad 
    @param ncs the number of supported cipher-suites
    @param ciphers an array of supported cipher-suites
    @return length of the output octad
 */
extern int cipherSuites(octad *CS,int ncs,int *ciphers); 

/**	@brief Flush IO buffer
 *
	@param session the TLS session structure
 */
extern void sendFlushIO(TLS_session *session);

/**	@brief Send a generic client message (as a single record) to the Server
 *
	@param session the TLS session structure
    @param rectype the record type
    @param version TLS version indication
    @param CM the client message to be sent
    @param EXT extensions to be added (or NULL if there are none)
    @param flush transmit immediately if true
 */
extern void sendClientMessage(TLS_session *session,int rectype,int version,octad *CM,octad *EXT,bool flush);

/**	@brief Send a preshared key binder message to the Server
 *
	@param session the TLS session structure
    @param BND binding HMAC of truncated transcript hash
    @param flush transmit immediately if true
 */
extern void sendBinder(TLS_session *session,octad *BND,bool flush);

/**	@brief Prepare and send Client Hello message to the Server, appending prepared extensions
 *
	@param session the TLS session structure
    @param version TLS version indication
    @param CH workspace octad in which to build client Hello
    @param CRN Random bytes
	@param already_agreed true if cipher suite previously negotiated, else false
    @param EXTENSIONS pre-prepared extensions
    @param extra length of preshared key binder to be sent later
    @param resume true if this hello is for handshae resumption
    @param flush transmit immediately
 */
extern void sendClientHello(TLS_session *session,int version,octad *CH,octad *CRN,bool already_agreed,octad *EXTENSIONS,int extra,bool resume,bool flush);

/**	@brief Prepare and send an Alert message to the Server
 *
	@param session the TLS session structure
    @param type the type of the Alert
 */
extern void sendAlert(TLS_session *session,int type);


/**	@brief Prepare and send a key update message to the Server
 *
	@param session the TLS session structure
    @param type the type of the update
 */
extern void sendKeyUpdate(TLS_session *session,int type);


/**	@brief Prepare and send a final handshake Verification message to the Server
 *
	@param session the TLS session structure
    @param CHF the client verify data HMAC
 */
extern void sendClientFinish(TLS_session *session,octad *CHF);

/**	@brief Prepare and send client certificate message to the Server
 *
	@param session the TLS session structure
    @param CERTCHAIN the client certificate chain
    @param CTX Certificate Context
 */
extern void sendClientCertificateChain(TLS_session *session,octad *CERTCHAIN,octad *CTX);

/**	@brief Send client Certificate Verify message to the Server
 *
	@param session the TLS session structure
    @param sigAlg the client's digital signature algorithm
    @param CCVSIG the client's signature
 */
extern void sendClientCertVerify(TLS_session *session, int sigAlg, octad *CCVSIG);


/**	@brief Indicate End of Early Data in message to the Server
 *
	@param session the TLS session structure
 */
extern void sendEndOfEarlyData(TLS_session *session);

/**	@brief Maps problem cause to Alert
 *
	@param rtn the cause of a problem (a function error return)
    @return type of Alert that should be sent to Server
 */
extern int alert_from_cause(int rtn);
#endif
