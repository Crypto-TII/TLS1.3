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

/**	@brief Parse out byte array from a pointer into an octad 
 *
	@param e the output byte array copied out from the octad M
    @param len the expected length of e
    @param M the input octad
    @param ptr a pointer into M, which advances after use
	@return the actual length of e extracted, and an error flag
 */
extern ret parsebytes(char *e,int len,octad *M,int &ptr);

/**	@brief Parse out an unsigned integer from a pointer into an octad 
 *
    @param M the input octad
	@param len the number of bytes in integer
    @param ptr a pointer into M, which advances after use
	@return the integer value, and an error flag
 */
extern ret parseInt(octad *M,int len,int &ptr);

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
	@param session the TLS session structure
	@return a positive indication of the record type, or a negative error return
 */
extern int getServerRecord(TLS_session *session);

/**	@brief Parse out an unsigned integer from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param session the TLS session structure
	@param len the number of bytes in integer
	@return the unsigned integer, and an error flag
 */
extern ret parseIntorPull(TLS_session *session,int len);

/**	@brief Parse out an octad from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param session the TLS session structure
    @param O the output octad
    @param len the expected length of the output octad O
	@return the actual length of O extracted, and an error flag
 */
extern ret parseoctadorPull(TLS_session *session,octad *O,int len);


/**	@brief Parse out a byte array from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param session the TLS session structure
    @param o the output bytes
    @param len the expected length of the output
	@return the actual length of o extracted, and an error flag
 */
extern ret parsebytesorPull(TLS_session *session,char *o,int len);

/**	@brief Return a pointer to an octad from a pointer into an octad, if necessary pulling in a new fragment
 *
	@param session the TLS session structure
    @param O a pointer to an octad contained within an octad IO
    @param len the expected length of the octad O
	@return the actual length of O extracted, and an error flag
 */
extern ret parseoctadorPullptrX(TLS_session *session,octad *O,int len);

/**	@brief Process response from server input
 *
	@param session the TLS1.3 session structure
    @param r return value to be processed
	@return true, if its a bad response requiring an abort
 */
extern bool badResponse(TLS_session *session,ret r);

/**	@brief Identify type of incoming message
 *
	@param session the TLS session structure
	@return negative error, zero for OK, or positive for message type
 */
extern ret seeWhatsNext(TLS_session *session);

/**	@brief Receive and parse Server Encrypted Extensions
 *
	@param session the TLS session structure
    @param enc_ext_expt ext structure containing server expectations
    @param enc_ext_resp ext structure containing server responses
	@return response structure
 */
extern ret getServerEncryptedExtensions(TLS_session *session,ee_status *enc_ext_expt,ee_status *enc_ext_resp);

/**	@brief Get Server proof that he owns the Certificate, by receiving and verifying its signature on transcript hash
 *
	@param session the TLS session structure
    @param SCVSIG the received signature on the transcript hash
    @param sigalg the type of the received signature
	@return response structure
 */
extern ret getServerCertVerify(TLS_session *session,octad *SCVSIG,int &sigalg);

/**	@brief Get final handshake message from Server, a HMAC on the transcript hash
 *
	@param session the TLS session structure
    @param HFIN an octad containing HMAC on transcript as calculated by Server
	@return response structure
 */
extern ret getServerFinished(TLS_session *session,octad *HFIN);

/**	@brief Receive and parse initial Server Hello
 *
	@param session the TLS session structure
    @param kex key exchange data
    @param CK an output Cookie
    @param PK the key exchange public value supplied by the Server
    @param pskid indicates if a pre-shared key was accepted, otherwise -1
	@return response structure
 */
extern ret getServerHello(TLS_session *session,/*int &cipher,*/int &kex,octad *CK,octad *PK,int &pskid);

/**	@brief Receive and check certificate chain
 *
	@param session the TLS session structure
    @param PUBKEY the public key extracted from the Server certificate 
    @param SIG signature (supplied as workspace)
	@return response structure
 */
extern ret getCheckServerCertificateChain(TLS_session *session,octad *PUBKEY,octad *SIG);

/**	@brief process a Certificate Request
 *
	@param session the TLS session structure
    @param context true if expecting a context
	@return response structure
 */
extern ret getCertificateRequest(TLS_session *session,bool context);



#endif