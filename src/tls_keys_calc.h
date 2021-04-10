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
#include "tls_crypto_api.h"

// transcript hash support

/**	@brief Accumulate octet into ongoing hashing 
 *
    @param O an octet to be included in hash
    @param h a hashing context
 */
extern void running_hash(octet *O,unihash *h);

/**	@brief Output current hash value
 *
    @param h a hashing context
    @param O an output octet containing current hash
 */
extern void transcript_hash(unihash *h,octet *O);

/**	@brief Calculate special synthetic hash calculation for first clientHello after retry request (RFC 8446 section 4.4.1)
 *
    @param O an octet containing clientHello
    @param E an octet containing clientHello extensions 
    @param h a hashing context

 */
extern void running_syn_hash(octet *O,octet *E,unihash *h);

/**	@brief Initiate a Crypto Context
 *
    @param C an AEAD encryption context
 */
extern void init_crypto_context(crypto *C);

/**	@brief Build a Crypto Context
 *
    @param C an AEAD encryption context
    @param K an encryption key
    @param IV an encryption Initialisation Vector
 */
extern void create_crypto_context(crypto *C,octet *K,octet *IV);

/**	@brief Increment a Crypto Context for the next record, updating IV
 *
    @param C an AEAD encryption context
 */
extern void increment_crypto_context(crypto *C);

/**	@brief Build a crypto context from an input raw Secret
 *
    @param cipher_suite the chosen cipher suite
    @param TS the input raw secret
    @param context an AEAD encryption context
 */
extern void GET_KEY_AND_IV(int cipher_suite,octet *TS,crypto *context);

/**	@brief Recover a pre-shared key from Resumption Master Secret and a nonce
 *
    @param sha length in bytes of SHA2 hashing output
    @param RMS the input resumption master secret
    @param NONCE the input nonce
    @param PSK the output pre-shared key
 */
extern void RECOVER_PSK(int sha,octet *RMS,octet *NONCE,octet *PSK);

/**	@brief Extract Early Secret Key and Binder Key from Preshared Key (External or Resumption)
 *
    @param sha length in bytes of SHA2 hashing output
    @param PSK the input pre-shared key, or NULL if not available
    @param ES the output early secret key
    @param BKE the output external binder key (or NULL if not required)
    @param BKR the output resumption binder key (or NULL if not required)
 */
extern void GET_EARLY_SECRET(int sha,octet *PSK,octet *ES,octet *BKE,octet *BKR);

/**	@brief Extract more secrets from Early Secret
 *
    @param sha length in bytes of SHA2 hashing output
    @param H a partial transcript hash
    @param ES the input early secret key
    @param CETS the output Client Early Traffic Secret (or NULL if not required)
    @param EEMS the output Early Exporter Master Secret (or NULL if not required)
 */
extern void GET_LATER_SECRETS(int sha,octet *H,octet *ES,octet *CETS,octet *EEMS);

/**	@brief Extract Handshake Secret from Shared Secret and Early Secret. Use Handshake Secret to extract Client and Server Handshake Traffic secrets 
 *
    @param sha length in bytes of SHA2 hashing output
    @param SS input Shared Secret
    @param ES the input early secret key
    @param H a partial transcript hash
    @param HS the output Handshake Secret
    @param CHTS the output Client Handshake Traffic Secret
    @param SHTS the output Server Handshake Traffic Secret
 */
extern void GET_HANDSHAKE_SECRETS(int sha,octet *SS,octet *ES, octet *H,octet *HS,octet *CHTS,octet *SHTS);

/**	@brief Extract Application Secret from Handshake Secret and Early Secret. Use Handshake Secret to extract Client and Server Application Traffic secrets 
 *
    @param sha length in bytes of SHA2 hashing output
    @param HS input Handshake Secret
    @param SFH an input partial transcript hash
    @param CFH an input partial transcript hash
    @param CTS the output Client Application Traffic Secret
    @param STS the output Server Application Traffic Secret
    @param EMS the output External Master Secret (or NULL if not required)
    @param RMS the output Resumption Master Secret (or NULL if not required)
 */
extern void GET_APPLICATION_SECRETS(int sha,octet *HS,octet *SFH,octet *CFH,octet *CTS,octet *STS,octet *EMS,octet *RMS);

/**	@brief Perform a Key Update on a crypto context
 *
    @param context an AEAD encryption context
    @param TS the updated Traffic secret
 */
extern void UPDATE_KEYS(crypto *context,octet *TS);

/**	@brief Test if data from Server is verified using server traffic secret and a transcript hash 
 *
    @param sha length in bytes of SHA2 hashing output
    @param SF the input verification data from Server
    @param STS the input Server Traffic Secret
    @param H the input partial transcript hash
    @return true is data is verified, else false
 */
extern bool IS_VERIFY_DATA(int sha,octet *SF,octet *STS,octet *H);

/**	@brief Create handshake verification data for Client to send to Server from client traffic secret and a transcript hash
 *
    @param sha length in bytes of SHA2 hashing output
    @param SF the output verification data
    @param CTS the input Client Traffic Secret
    @param H the input partial transcript hash
 */
extern void VERIFY_DATA(int sha,octet *SF,octet *CTS,octet *H);

#endif
