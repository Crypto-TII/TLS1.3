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
	@param client the socket connection to the Server
 */
extern void sendCCCS(Socket &client);

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

/**	@brief Add Maximum Fragment Length extension to under-construction Extensions Octet
 *
	@param EXT the extensions octad which is being built
    @param mode the proposed maximum fragment size
 */  
extern void addMFLExt(octad *EXT,int mode);

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

/**	@brief Generate 32-byte random octad
 *
	@param RN the output 32-byte octad 
    @return length of output octad
 */
extern int clientRandom(octad *RN);

/**	@brief Create 32-byte random session ID octad
 *
	@param SI the output random octad 
    @return length of output octad
 */
extern int sessionID(octad *SI);

/**	@brief Build a cipher-suites octad from supported ciphers
 *
	@param CS the output cipher-suite octad 
    @param ncs the number of supported cipher-suites
    @param ciphers an array of supported cipher-suites
    @return length of the output octad
 */
extern int cipherSuites(octad *CS,int ncs,int *ciphers); 

/**	@brief Send a generic client message (as a single record) to the Server
 *
	@param client the socket connection to the Server
    @param rectype the record type
    @param version TLS version indication
    @param send the cryptographic key under which the message is encrypted (or NULL if no encryption)
    @param CM the client message to be sent
    @param EXT extensions to be added (or NULL if there are none)
    @param IO the workspace octad in which to construct the encrypted message
 */
extern void sendClientMessage(Socket &client,int rectype,int version,crypto *send,octad *CM,octad *EXT,octad *IO);

/**	@brief Send a preshared key binder message to the Server
 *
	@param client the socket connection to the Server
    @param B workspace octad in which to construct binder message
    @param BND binding HMAC of truncated transcript hash
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendBinder(Socket &client,octad *B,octad *BND,octad *IO);

/**	@brief Prepare and send Client Hello message to the Server, appending prepared extensions
 *
	@param client the socket connection to the Server
    @param version TLS version indication
    @param CH workspace octad in which to build client Hello
    @param nsc the number of supported cipher-suites
    @param ciphers an array of supported cipher-suites
    @param CID random session ID (generated and used internally, and output here)
    @param EXTENSIONS pre-prepared extensions
    @param extra length of preshared key binder to be sent later
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendClientHello(Socket &client,int version,octad *CH,int nsc,int *ciphers,octad *CID,octad *EXTENSIONS,int extra,octad *IO);

/**	@brief Prepare and send an Alert message to the Server
 *
	@param client the socket connection to the Server
    @param type the type of the Alert
    @param send the cryptographic key under which the alert message is encrypted (or NULL if no encryption)
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendClientAlert(Socket &client,int type,crypto *send,octad *IO);

/**	@brief Prepare and send a final handshake Verification message to the Server
 *
	@param client the socket connection to the Server
    @param send the cryptographic key under which the verification message is encrypted
    @param h the current transcript hash up to this point
    @param CHF the client verify data HMAC
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendClientFinish(Socket &client,crypto *send,unihash *h,octad *CHF,octad *IO);

/**	@brief Prepare and send client certificate message to the Server
 *
	@param client the socket connection to the Server
    @param send the cryptographic key under which the certificate message is encrypted
    @param h the current transcript hash up to this point
    @param CERTCHAIN the client certificate chain
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendClientCertificateChain(Socket &client,crypto *send, unihash *h,octad *CERTCHAIN,octad *IO);

/**	@brief Send client Certificate Verify message to the Server
 *
	@param client the socket connection to the Server
    @param send the cryptographic key under which the certificate message is encrypted
    @param h the current transcript hash up to this point
    @param sigAlg the client's digital signature algorithm
    @param CCVSIG the client's signature
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendClientCertVerify(Socket &client,crypto *send, unihash *h, int sigAlg, octad *CCVSIG,octad *IO);


/**	@brief Indicate End of Early Data in message to the Server
 *
	@param client the socket connection to the Server
    @param send the cryptographic key under which the  message is encrypted
    @param h the current transcript hash up to this point
    @param IO the workspace octad in which to construct the overall message
 */
extern void sendEndOfEarlyData(Socket &client,crypto *send,unihash *h,octad *IO);

/**	@brief Maps problem cause to Alert
 *
	@param rtn the cause of a problem (a function error return)
    @return type of Alert that should be sent to Server
 */
extern int alert_from_cause(int rtn);
#endif
