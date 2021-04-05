/**
 * @file tls_client_recv.h
 * @author Mike Scott
 * @brief Process Input received from the Server
 *
 */
// Process input received from Server

#ifndef TLS_CLIENT_RECV_H
#define TLS_CLIENT_RECV_H

#include "core.h"
#include "tls1_3.h"
#include "tls_sockets.h"
#include "tls_keys_calc.h"

using namespace core;

/**	@brief Parse out an Octet from a pointer into an Octet 
 *
	@param E the output octet copied out from the octet M
    @param len the expected length of the output octet E
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the actual length of E extracted, and an error flag
 */
extern ret parseOctet(octet *E,int len,octet *M,int &ptr);

/**	@brief Parse out a 16-bit unsigned integer from a pointer into an Octet 
 *
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the 16-bit integer value, and an error flag
 */
extern ret parseInt16(octet *M,int &ptr);

/**	@brief Parse out a 24-bit unsigned integer from a pointer into an Octet 
 *
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the 24-bit integer value, and an error flag
 */
extern ret parseInt24(octet *M,int &ptr);

/**	@brief Parse out a 32-bit unsigned integer from a pointer into an Octet 
 *
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the 32-bit integer value, and an error flag
 */
extern ret parseInt32(octet *M,int &ptr);

/**	@brief Parse out an unsigned byte from a pointer into an Octet 
 *
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the unsigned byte, and an error flag
 */
extern ret parseByte(octet *M,int &ptr);

/**	@brief Return a pointer to an Octet from a pointer into an Octet 
 *
	@param E a pointer to an octet contained within an octet M
    @param len the expected length of the octet E
    @param M the input octet
    @param ptr a pointer into M, which advances after use
	@return the actual length of E, and an error flag
 */
extern ret parseOctetptr(octet *E,int len,octet *M,int &ptr);

/**	@brief Read a record from the Server, a fragment of a full protocol message
 *
	@param client the socket connection to the Server
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
    @param IO the received record, a protocol message fragment
	@return a positive indication of the record type, or a negative error return
 */
extern int getServerFragment(Socket &client,crypto *recv,octet *IO);

/**	@brief Parse out an unsigned byte from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the unsigned byte, and an error flag
 */
extern ret parseByteorPull(Socket &client,octet *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 32-bit unsigned integer from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 32-bit integer value, and an error flag
 */
extern ret parseInt32orPull(Socket &client,octet *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 24-bit unsigned integer from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 24-bit integer value, and an error flag
 */
extern ret parseInt24orPull(Socket &client,octet *IO,int &ptr,crypto *recv);

/**	@brief Parse out a 16-bit unsigned integer from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the 16-bit integer value, and an error flag
 */
extern ret parseInt16orPull(Socket &client,octet *IO,int &ptr,crypto *recv);

/**	@brief Parse out an octet from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param O the output octet
    @param len the expected length of the output octet O
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the actual length of O extracted, and an error flag
 */
extern ret parseOctetorPull(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv);

/**	@brief Return a pointer to an Octet from a pointer into an Octet, if necessary pulling in a new fragment
 *
	@param client the socket connection to the Server
    @param O a pointer to an octet contained within an octet IO
    @param len the expected length of the octet O
    @param IO the input octet
    @param ptr a pointer into IO, which advances after use
    @param recv the cryptographic key under which the fragment is encrypted, or NULL if not encrypted
	@return the actual length of O extracted, and an error flag
 */
extern ret parseOctetorPullptr(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv);

/**	@brief Identify type of message
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept input
    @param recv the cryptographic key under which communications are encrypted
    @param trans_hash the current and updated transcript hash
	@return negative error, zero for OK, or positive for message type
 */
extern int getWhatsNext(Socket &client,octet *IO,crypto *recv,unihash *trans_hash);

/**	@brief Receive and parse Server Encrypted Extensions
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept input
    @param recv the cryptographic key under which the extensions are encrypted
    @param trans_hash the current and updated transcript hash
    @param early_data_accepted an output boolean indicating if early data was accepted
	@return negative error, zero for OK, or positive for informative response
 */
extern int getServerEncryptedExtensions(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,bool &early_data_accepted);

/**	@brief Get Server proof that he owns the Certificate, by receiving and verifying its signature on transcript hash
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept server input
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param SCVSIG the received signature on the transcript hash
    @param sigalg the type of the received signature
	@return negative error, zero for OK, or positive for informative response
 */
extern int getServerCertVerify(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *SCVSIG,int &sigalg);

/**	@brief Get final handshake message from Server, a HMAC on the transcript hash
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept input
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param HFIN an octet containing HMAC on transcript as calculated by Server
	@return negative error, zero for OK, or positive for informative response
 */
extern int getServerFinished(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *HFIN);

/**	@brief Receive and parse initial Server Hello
 *
	@param client the socket connection to the Server
    @param SH an Octet to accept server input
    @param cipher the agreed cipher suite
    @param kex key exchange data
    @param CID random session identity
    @param CK an output Cookie
    @param PK the key exchange public value supplied by the Server
    @param pskid indicates if a pre-shared key was accepted, otherwise -1
	@return negative error, zero for OK, or positive for informative response
 */
extern int getServerHello(Socket &client,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK,int &pskid);

/**	@brief Receive and check certificate chain
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept server supplied certificate chain
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param hostname the Server name which the client wants confirmed by Server Certificate
    @param PUBKEY the public key extracted from the Server certificate 
	@return negative error, zero for OK, or positive for informative response
 */
extern int getCheckServerCertificateChain(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,char *hostname,octet *PUBKEY);

/**	@brief process a Certificate Request
 *
	@param client the socket connection to the Server
    @param IO an Octet to accept server supplied certificate request
    @param recv the cryptographic key under which the server response is encrypted
    @param trans_hash the current and updated transcript hash
    @param nalgs the number of acceptable signature algorithms
    @param an array of nalgs signature algorithms
	@return negative error, zero for OK, or positive for informative response
 */
extern int getCertificateRequest(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,int &nalgs,int *sigalgs);

#endif