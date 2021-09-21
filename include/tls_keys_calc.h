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

/**	@brief Accumulate octad into ongoing hashing 
 *
    @param O an octad to be included in hash
    @param h a hashing context
 */
extern void runningHash(octad *O,unihash *h);

/**	@brief Output current hash value
 *
    @param h a hashing context
    @param O an output octad containing current hash
 */
extern void transcriptHash(unihash *h,octad *O);

/**	@brief Calculate special synthetic hash calculation for first clientHello after retry request (RFC 8446 section 4.4.1)
 *
    @param O an octad containing clientHello
    @param E an octad containing clientHello extensions 
    @param h a hashing context

 */
extern void runningSyntheticHash(octad *O,octad *E,unihash *h);

/**	@brief Initiate a Crypto Context
 *
    @param C an AEAD encryption context
 */
extern void initCryptoContext(crypto *C);

/**	@brief Build a Crypto Context
 *
    @param C an AEAD encryption context
    @param K an encryption key
    @param IV an encryption Initialisation Vector
 */
extern void updateCryptoContext(crypto *C,octad *K,octad *IV);

/**	@brief Increment a Crypto Context for the next record, updating IV
 *
    @param C an AEAD encryption context
 */
extern void incrementCryptoContext(crypto *C);

/**	@brief Build a crypto context from an input raw Secret and an agreed cipher_suite 
 *
    @param cipher_suite the chosen cipher suite
    @param TS the input raw secret
    @param context an AEAD encryption context
 */
extern void createCryptoContext(int cipher_suite,octad *TS,crypto *context);

/**	@brief Recover a pre-shared key from Resumption Master Secret and a nonce
 *
    @param cipher_suite the active cipher suite
    @param RMS the input resumption master secret
    @param NONCE the input nonce
    @param PSK the output pre-shared key
 */
extern void recoverPSK(int cipher_suite,octad *RMS,octad *NONCE,octad *PSK);

/**	@brief Extract Early Secret Key and Binder Key from Preshared Key (External or Resumption)
 *
    @param htype hash algorithm
    @param PSK the input pre-shared key, or NULL if not available
    @param ES the output early secret key
    @param BKE the output external binder key (or NULL if not required)
    @param BKR the output resumption binder key (or NULL if not required)
 */
extern void deriveEarlySecrets(int htype,octad *PSK,octad *ES,octad *BKE,octad *BKR);

/**	@brief Extract more secrets from Early Secret
 *
    @param htype hash algorithm
    @param H a partial transcript hash
    @param ES the input early secret key
    @param CETS the output Client Early Traffic Secret (or NULL if not required)
    @param EEMS the output Early Exporter Master Secret (or NULL if not required)
 */
extern void deriveLaterSecrets(int htype,octad *H,octad *ES,octad *CETS,octad *EEMS);

/**	@brief Extract Handshake Secret from Shared Secret and Early Secret. Use Handshake Secret to extract Client and Server Handshake Traffic secrets 
 *
    @param htype hash algorithm
    @param SS input Shared Secret
    @param ES the input early secret key
    @param H a partial transcript hash
    @param HS the output Handshake Secret
    @param CHTS the output Client Handshake Traffic Secret
    @param SHTS the output Server Handshake Traffic Secret
 */
extern void deriveHandshakeSecrets(int htype,octad *SS,octad *ES, octad *H,octad *HS,octad *CHTS,octad *SHTS);

/**	@brief Extract Application Secret from Handshake Secret and Early Secret. Use Handshake Secret to extract Client and Server Application Traffic secrets 
 *
    @param htype hash algorithm
    @param HS input Handshake Secret
    @param SFH an input partial transcript hash
    @param CFH an input partial transcript hash
    @param CTS the output Client Application Traffic Secret
    @param STS the output Server Application Traffic Secret
    @param EMS the output External Master Secret (or NULL if not required)
    @param RMS the output Resumption Master Secret (or NULL if not required)
 */
extern void deriveApplicationSecrets(int htype,octad *HS,octad *SFH,octad *CFH,octad *CTS,octad *STS,octad *EMS,octad *RMS);

/**	@brief Perform a Key Update on a crypto context
 *
    @param context an AEAD encryption context
    @param TS the updated Traffic secret
 */
extern void deriveUpdatedKeys(crypto *context,octad *TS);

/**	@brief Test if data from Server is verified using server traffic secret and a transcript hash 
 *
    @param htype hash algorithm
    @param SF the input verification data from Server
    @param STS the input Server Traffic Secret
    @param H the input partial transcript hash
    @return true is data is verified, else false
 */
extern bool checkVeriferData(int htype,octad *SF,octad *STS,octad *H);

/**	@brief Create handshake verification data for Client to send to Server from client traffic secret and a transcript hash
 *
    @param htype hash algorithm
    @param SF the output verification data
    @param CTS the input Client Traffic Secret
    @param H the input partial transcript hash
 */
extern void deriveVeriferData(int htype,octad *SF,octad *CTS,octad *H);

/**	@brief verify Server's signature on protocol transcript
 *
	@param sigalg the algorithm used for digital signature
    @param SCVSIG the input signature on the transcript
    @param H the transcript hash 
    @param CERTPK the Server's public key
	@return true if signature is verified, else returns false
 */
extern bool checkServerCertVerifier(int sigalg,octad *SCVSIG,octad *H,octad *CERTPK);

/**	@brief Create Cert Verify message, as a digital signature on some TLS1.3 specific message+transcript hash
 *
    @param sigAlg the signature algorithm
    @param H a transcript hash to be signed
    @param KEY the Client's private key
    @param CCVSIG the output digital signature
 */
extern void createClientCertVerifier(int sigAlg,octad *H,octad *KEY,octad *CCVSIG);

#endif
