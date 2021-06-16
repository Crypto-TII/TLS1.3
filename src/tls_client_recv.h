/**
 * @file tls_client_recv.h
 * @author Mike Scott
 * @brief Process Input received from the Server
 *
 */
// Process input received from Server

#ifndef TLS_CLIENT_RECV_H
#define TLS_CLIENT_RECV_H

#include "tls_sal.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"
#include "tls_client_send.h"

/**	@brief Parse out an octad from a pointer into an octad 
 *
	@param E the output octad copied out from the octad M
    @param len the expected length of the output octad E
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the actual length of E extracted, and an error flag
 */
extern ret parseoctad(octad *E,int len,octad *M,int &ptr);

/**	@brief Parse out a 16-bit unsigned integer from a pointer into an octad 
 *
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the 16-bit integer value, and an error flag
 */
extern ret parseInt16(octad *M,int &ptr);

/**	@brief Parse out a 24-bit unsigned integer from a pointer into an octad 
 *
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the 24-bit integer value, and an error flag
 */
extern ret parseInt24(octad *M,int &ptr);

/**	@brief Parse out a 32-bit unsigned integer from a pointer into an octad 
 *
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the 32-bit integer value, and an error flag
 */
extern ret parseInt32(octad *M,int &ptr);

/**	@brief Parse out an unsigned byte from a pointer into an octad 
 *
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the unsigned byte, and an error flag
 */
extern ret parseByte(octad *M,int &ptr);

/**	@brief Return a pointer to an octad from a pointer into an octad 
 *
	@param E a pointer to an octad contained within an octad M
    @param len the expected length of the octad E
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the actual length of E, and an error flag
 */
extern ret parseoctadptr(octad *E,int len,octad *M,int &ptr);

/**	@brief Read a record from the Server, a fragment of a full protocol message
 *
	@param client the socket connection to the Server
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
    @param IO the received record, a protocol message fragment
	@return a positive indication of the record type, or a negative error return
 */
extern int getServerFragment(Socket &client,crypto *recv,octad *IO);

/**	@brief Parse out an unsigned byte from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the unsigned byte, and an error flag
 */
extern ret parseByteorPull(Socket &client,octad *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 32-bit unsigned integer from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 32-bit integer value, and an error flag
 */
extern ret parseInt32orPull(Socket &client,octad *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 24-bit unsigned integer from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 24-bit integer value, and an error flag
 */
extern ret parseInt24orPull(Socket &client,octad *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 16-bit unsigned integer from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 16-bit integer value, and an error flag
 */
extern ret parseInt16orPull(Socket &client,octad *IO,int &ptr,crypto *recv);

/**	@brief Parse out an octad from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param O the output octad
    @param len the expected length of the output octad O
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the actual length of O extracted, and an error flag
 */
extern ret parseoctadorPull(Socket &client,octad *O,int len,octad *IO,int &ptr,crypto *recv);

/**	@brief Return a pointer to an octad from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param O a pointer to an octad contained within an octad IO
    @param len the expected length of the octad O
    @param IO the input octad
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the actual length of O extracted, and an error flag
 */
extern ret parseoctadorPullptr(Socket &client,octad *O,int len,octad *IO,int &ptr,crypto *recv);

/**	@brief Process response from server input
 *
	@param client the socket connection to the Server
    @param send the cryptographic key under which an outgoing alert may be encrypted
    @param r return value to be processed
	@return true, if its a bad response requiring an abort
 */
extern bool badResponse(Socket &client,crypto *send,ret r);

/**	@brief Identify type of message
 *
	@param client the socket connection to the Server
    @param IO an octad to accept input
    @param recv the cryptographic key under which communications are encrypted
    @param trans_hash the current and updated transcript hash
	@return negative error, zero for OK, or positive for message type
 */
extern ret getWhatsNext(Socket &client,octad *IO,crypto *recv,unihash *trans_hash);

/**	@brief Receive and parse Server Encrypted Extensions
 *
	@param client the socket connection to the Server
    @param IO an octad to accept input
    @param recv the cryptographic key under which the extensions are encrypted
    @param trans_hash the current and updated transcript hash
    @param enc_ext_expt ext structure containing server expectations
    @param enc_ext_resp ext structure containing server responses
	@return response structure
 */
extern ret getServerEncryptedExtensions(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,ee_expt *enc_ext_expt,ee_resp *enc_ext_resp);

/**	@brief Get Server proof that he owns the Certificate, by receiving and verifying its signature on transcript hash
 *
	@param client the socket connection to the Server
    @param IO an octad to accept server input
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param SCVSIG the received signature on the transcript hash
    @param sigalg the type of the received signature
	@return response structure
 */
extern ret getServerCertVerify(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,octad *SCVSIG,int &sigalg);

/**	@brief Get final handshake message from Server, a HMAC on the transcript hash
 *
	@param client the socket connection to the Server
    @param IO an octad to accept input
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param HFIN an octad containing HMAC on transcript as calculated by Server
	@return response structure
 */
extern ret getServerFinished(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,octad *HFIN);

/**	@brief Receive and parse initial Server Hello
 *
	@param client the socket connection to the Server
    @param SH an octad to accept server input
    @param cipher the agreed cipher suite
    @param kex key exchange data
    @param CID random session identity
    @param CK an output Cookie
    @param PK the key exchange public value supplied by the Server
    @param pskid indicates if a pre-shared key was accepted, otherwise -1
	@return response structure
 */
extern ret getServerHello(Socket &client,octad* SH,int &cipher,int &kex,octad *CID,octad *CK,octad *PK,int &pskid);

/**	@brief Receive and check certificate chain
 *
	@param client the socket connection to the Server
    @param IO an octad to accept server supplied certificate chain
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param hostname the Server name which the client wants confirmed by Server Certificate
    @param PUBKEY the public key extracted from the Server certificate 
	@return response structure
 */
extern ret getCheckServerCertificateChain(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,char *hostname,octad *PUBKEY);

/**	@brief process a Certificate Request
 *
	@param client the socket connection to the Server
    @param IO an octad to accept server supplied certificate request
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param nalgs the number of acceptable signature algorithms
    @param sigalgs an array of nalgs signature algorithms
	@return response structure
 */
extern ret getCertificateRequest(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,int &nalgs,int *sigalgs);



#endif