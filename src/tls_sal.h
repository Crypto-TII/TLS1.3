/**
 * @file tls_sal.h
 * @author Mike Scott
 * @brief Security Abstraction Layer for TLS 
 *
 */
// Process input received from Server

#ifndef TLS_SAL_H
#define TLS_SAL_H

// Use MIRACL core library

#include "tls1_3.h"

/**
 * @brief Universal Hash structure */
typedef struct 
{
    char state[TLS_MAX_HASH_STATE];   /**< hash function state */
    int htype;                        /**< The hash type (typically SHA256) */
} unihash;

/** @brief Return name of SAL provider
*
    @return name of SAL provider
*/
extern char *SAL_name();

/** @brief Return supported ciphers
*
    @param ciphers array of supported ciphers in preferred order
    @return number of supported ciphers
*/
extern int SAL_ciphers(int *ciphers);

/** @brief Return supported groups in preferred order
*
    @param groups array of supported groups
    @return number of supported groups
*/
extern int SAL_groups(int *groups);

/** @brief Return supported TLS signature algorithms in preferred order 
*
    @param sigAlgs array of supported signature algorithms
    @return number of supported groups
*/
extern int SAL_sigs(int *sigAlgs);

/** @brief Return supported TLS signature algorithms for Certificates in preferred order
*
    @param sigAlgsCert array of supported signature algorithms for Certificates
    @return number of supported groups
*/
extern int SAL_sigCerts(int *sigAlgsCert);

/** @brief Initialise libraries
*
    @return return true if successful, else false
*/
extern bool SAL_initLib();

/** @brief return hash type asspciated with a cipher suite
*
    @param cipher_suite a TLS cipher suite
    @return hash function output length
*/
extern int SAL_hashType(int cipher_suite);

/** @brief return output length of hash function associated with a hash type
*
    @param hash_type a TLS hash type
    @return hash function output length
*/
extern int SAL_hashLen(int hash_type);

/** @brief get a random byte
*
    @return a random byte
*/
extern int SAL_randomByte();

/** @brief get a random octad
*
    @param len number of random bytes
    @param R octad to be filled with random bytes
*/
extern void SAL_randomOctad(int len, octad *R);

/**	@brief HKDF Extract function
 *
	@param sha hash algorithm
	@param PRK an output Key
    @param SALT public input salt
    @param IKM raw secret keying material
 */
extern void SAL_hkdfExtract(int sha,octad *PRK,octad *SALT,octad *IKM);

/**	@brief Special HKDF Expand function (for TLS)
 *
	@param htype hash algorithm
	@param OKM an expanded output Key
    @param olen is the desired length of the expanded key
    @param PRK is the fixed length input key
    @param Label is public label information
    @param CTX is public context information
 */
extern void SAL_hkdfExpandLabel(int htype,octad *OKM,int olen,octad *PRK,octad *Label,octad *CTX);

/**	@brief simple HMAC function
 *
	@param htype hash algorithm
	@param T an output tag
    @param K an input key, or salt
    @param M an input message
 */
extern void SAL_hmac(int htype,octad *T,octad *K,octad *M);

/**	@brief simple HASH of nothing function
 *
	@param sha the SHA2 function output length (32,48 or 64)
	@param H the output hash
 */
extern void SAL_hashNull(int sha,octad *H);

// hash functions

/**	@brief Initiate Hashing context
 *
	@param hlen length in bytes of SHA2 hashing output
    @param h a hashing context
 */
extern void SAL_hashInit(int hlen,unihash *h);

/**	@brief Hash process a byte
 *
    @param h a hashing context
    @param b the byte to be included in hash
 */
extern void SAL_hashProcess(unihash *h,int b);

/**	@brief Hash finish and output
 *
    @param h a hashing context
    @param d the current output digest of an ongoing hashing operation
    @return hash output length
 */
extern int SAL_hashOutput(unihash *h,char *d);

/**	@brief AEAD encryption 
 *
	@param send the AES key and IV
    @param hdrlen the length of the header
    @param hdr the header bytes
    @param ptlen the plaintext length
    @param pt the input plaintext and output ciphertext
    @param TAG the output authentication tag
 */
extern void SAL_aeadEncrypt(crypto *send,int hdrlen,char *hdr,int ptlen,char *pt,octad *TAG);

/**	@brief AEAD decryption 
 *
	@param recv the AES key and IV
    @param hdrlen the length of the header
    @param hdr the header bytes
    @param ctlen the ciphertext length
    @param ct the input ciphertext and output plaintext
    @param TAG the expected authentication tag
    @return -1 if tag is wrong, else 0
 */
extern int SAL_aeadDecrypt(crypto *recv,int hdrlen,char *hdr,int ctlen,char *ct,octad *TAG);

/**	@brief generate a public/private key pair in an approved group for a key exchange
 *
    @param group the cryptographic group used to generate the key pair
    @param SK the output Private Key
    @param PK the output Public Key
 */
extern void SAL_generateKeyPair(int group,octad *SK,octad *PK);

/**	@brief generate a Diffie-Hellman shared secret
 *
    @param group the cryptographic group used to generate the shared secret
    @param SK the input client private key
    @param PK the input server public Key
    @param SS the output shared secret
 */
extern void SAL_generateSharedSecret(int group,octad *SK,octad *PK,octad *SS);

/**	@brief Verify a generic certificate signature
 *
    @param sigAlg the signature type
    @param CERT the input certificate that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool SAL_certSignatureVerify(int sigAlg,octad *CERT,octad *SIG,octad *PUBKEY);

/**	@brief Verify a generic TLS transcript signature
 *
    @param sigAlg the signature type
    @param TRANS the input transcript hash that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool SAL_tlsSignatureVerify(int sigAlg,octad *TRANS,octad *SIG,octad *PUBKEY);

/**	@brief Apply a generic TLS transcript signature
 *
    @param sigAlg the signature type
    @param KEY the private key used to form the signature
    @param TRANS the input transcript hash to be signed
    @param SIG the output signature
 */
extern void SAL_tlsSignature(int sigAlg,octad *KEY,octad *TRANS,octad *SIG);


#endif