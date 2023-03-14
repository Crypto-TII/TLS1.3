/**
 * @file tls_keys_calc.h
 * @author Mike Scott
 * @brief TLS 1.3 crypto support functions
 *
 */

// TLS1.3 crypto support functions
#ifndef TLS_KEYS_CALC_H
#define TLS_KEYS_CALC_H

#include "tls1_3.h"
#include "tls_sal.h"
#include "tls_client_recv.h"

// transcript hash support
/** @brief Initialise Transcript hash
 *
    @param session the TLS session structure
 */
extern void initTranscriptHash(TLS_session *session);

/** @brief Accumulate octad into ongoing hashing 
 *
    @param session the TLS session structure
    @param O an octad to be included in hash

 */
extern void runningHash(TLS_session *session,octad *O);

/** @brief Accumulate transcript hash from IO buffer
 *
    @param session the TLS session structure

 */
extern void runningHashIO(TLS_session *session);

/** @brief rewind the IO buffer
 *
    @param session the TLS session structure

 */
extern void rewindIO(TLS_session *session);


/** @brief Accumulate transcript hash and from IO buffer, and rewind IO buffer
 *
    @param session the TLS session structure

 */
extern void runningHashIOrewind(TLS_session *session);


/** @brief Output current hash value
 *
    @param session the TLS session structure
    @param O an output octad containing current hash
 */
extern void transcriptHash(TLS_session *session,octad *O);

/** @brief Calculate special synthetic hash calculation for first clientHello after retry request (RFC 8446 section 4.4.1)
 *
     @param session the TLS session structure
    @param O an octad containing clientHello
    @param E an octad containing clientHello extensions 

 */
extern void runningSyntheticHash(TLS_session *session,octad *O,octad *E);

/** @brief Initiate a Crypto Context
 *
    @param C an AEAD encryption context
 */
extern void initCryptoContext(crypto *C);

/** @brief Build a Crypto Context
 *
    @param C an AEAD encryption context
    @param K an encryption key
    @param IV an encryption Initialisation Vector
 */
extern void updateCryptoContext(crypto *C,octad *K,octad *IV);

/** @brief Increment a Crypto Context for the next record, updating IV
 *
    @param C an AEAD encryption context
 */
extern void incrementCryptoContext(crypto *C);


/** @brief Create a crypto context from an input raw Secret and an agreed cipher_suite 
 *
    @param cipher the chosen cipher site
    @param TS the input raw secret
    @param context the output crypto conetext
 */
extern void createCryptoContext(int cipher,octad *TS,crypto *context);

/** @brief Build a crypto context for transmission from an input raw Secret and an agreed cipher_suite 
 *
    @param session TLS session structure
    @param TS the input raw secret
 */
extern void createSendCryptoContext(TLS_session *session,octad *TS);

/** @brief Build a crypto context for reception from an input raw Secret and an agreed cipher_suite 
 *
    @param session TLS session structure
    @param TS the input raw secret
 */
extern void createRecvCryptoContext(TLS_session *session,octad *TS);

/** @brief Recover pre-shared key from the Resumption Master Secret and store with ticket
 *
    @param session the TLS session structure
 */
extern void recoverPSK(TLS_session *session);

/** @brief Extract Early Secret Key and Binder Key from Preshared Key (External or Resumption)
 *
    @param htype hash algorithm
    @param PSK the input pre-shared key, or NULL if not available
    @param ES the output early secret key
    @param BKE the output external binder key (or NULL if not required)
    @param BKR the output resumption binder key (or NULL if not required)
 */
extern void deriveEarlySecrets(int htype,octad *PSK,octad *ES,octad *BKE,octad *BKR);

/** @brief Extract more secrets from Early Secret
 *
    @param htype hash algorithm
    @param H a partial transcript hash
    @param ES the input early secret key
    @param CETS the output Client Early Traffic Secret (or NULL if not required)
    @param EEMS the output Early Exporter Master Secret (or NULL if not required)
 */
extern void deriveLaterSecrets(int htype,octad *H,octad *ES,octad *CETS,octad *EEMS);

/** @brief Extract Handshake Secret from Shared Secret and Early Secret. Use Handshake Secret to extract Client and Server Handshake Traffic secrets 
 *
     @param session the TLS session structure
    @param SS input Shared Secret
    @param ES the input early secret key
    @param H a partial transcript hash
 */
extern void deriveHandshakeSecrets(TLS_session *session,octad *SS,octad *ES, octad *H);

/** @brief Extract Application Secret from Handshake Secret and Early Secret. Use Handshake Secret to extract Client and Server Application Traffic secrets 
 *
     @param session the TLS session structure   
    @param SFH an input partial transcript hash
    @param CFH an input partial transcript hash
    @param EMS the output External Master Secret (or NULL if not required)
 */
extern void deriveApplicationSecrets(TLS_session *session,octad *SFH,octad *CFH,octad *EMS);

/** @brief Perform a Key Update on a crypto context
 *
    @param context an AEAD encryption context
    @param TS the updated Traffic secret
 */
extern void deriveUpdatedKeys(crypto *context,octad *TS);

/** @brief Test if data from Server is verified using server traffic secret and a transcript hash 
 *
    @param htype hash algorithm
    @param SF the input verification data from Server
    @param STS the input Server Traffic Secret
    @param H the input partial transcript hash
    @return true is data is verified, else false
 */
extern bool checkVeriferData(int htype,octad *SF,octad *STS,octad *H);

/** @brief Create handshake verification data for Client to send to Server from client traffic secret and a transcript hash
 *
    @param htype hash algorithm
    @param SF the output verification data
    @param CTS the input Client Traffic Secret
    @param H the input partial transcript hash
 */
extern void deriveVeriferData(int htype,octad *SF,octad *CTS,octad *H);

/** @brief verify Server's signature on protocol transcript
 *
    @param sigalg the algorithm used for digital signature
    @param SCVSIG the input signature on the transcript
    @param H the transcript hash 
    @param CERTPK the Server's public key
    @return true if signature is verified, else returns false
 */
extern bool checkServerCertVerifier(int sigalg,octad *SCVSIG,octad *H,octad *CERTPK);

/** @brief Create Cert Verify message, as a digital signature on some TLS1.3 specific message+transcript hash
 *
    @param sigAlg the signature algorithm
    @param H a transcript hash to be signed
    @param KEY the Client's private key
    @param CCVSIG the output digital signature
 */
extern void createClientCertVerifier(int sigAlg,octad *H,octad *KEY,octad *CCVSIG);

#endif
