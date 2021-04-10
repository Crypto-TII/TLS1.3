/**
 * @file tls_crypto_api.h
 * @author Mike Scott
 * @brief Cryptographic support functions for TLS
 *
 */
// Process input received from Server

#ifndef TLS_CRYPTO_API_H
#define TLS_CRYPTO_API_H

#include "core.h"
#include "tls1_3.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "ecdh_C25519.h"
#include "rsa_RSA2048.h"
#include "rsa_RSA4096.h"

/**
 * @brief Universal Hash structure */
typedef struct 
{
    hash256 sh32;       /**< A SHA256 instance */ 
    hash512 sh64;       /**< A SHA384/512 instance */
    int hlen;           /**< The length of the SHA output in bytes (32/48/64) */
} unihash;

// hash functions

/**	@brief Initiate Hashing context
 *
	@param hlen length in bytes of SHA2 hashing output
    @param h a hashing context
 */
extern void Hash_Init(int hlen,unihash *h);

/**	@brief Hash process a byte
 *
    @param h a hashing context
    @param b the byte to be included in hash
 */
extern void Hash_Process(unihash *h,int b);

/**	@brief Hash output
 *
    @param h a hashing context
    @param d the current output digest of an ongoing hashing operation
 */
extern void Hash_Output(unihash *h,char *d);

/**	@brief AES_GCM encryption 
 *
	@param send the AES key and IV
    @param hdrlen the length of the header
    @param hdr the header bytes
    @param ptlen the plaintext length
    @param pt the input plaintext and output ciphertext
    @param TAG the output authentication tag
 */
extern void AES_GCM_ENCRYPT(crypto *send,int hdrlen,char *hdr,int ptlen,char *pt,octet *TAG);

/**	@brief AES_GCM decryption 
 *
	@param recv the AES key and IV
    @param hdrlen the length of the header
    @param hdr the header bytes
    @param ctlen the ciphertext length
    @param ct the input ciphertext and output plaintext
    @param TAG the output authentication tag
 */
extern void AES_GCM_DECRYPT(crypto *recv,int hdrlen,char *hdr,int ctlen,char *ct,octet *TAG);

/**	@brief generate a public/private key pair in an approved group for a key exchange
 *
    @param RNG a random number generator
    @param group the cryptographic group used to generate the key pair
    @param SK the output Private Key
    @param PK the output Public Key
 */
extern void GENERATE_KEY_PAIR(csprng *RNG,int group,octet *SK,octet *PK);

/**	@brief generate a Diffie-Hellman shared secret
 *
    @param group the cryptographic group used to generate the shared secret
    @param SK the input client private key
    @param PK the input server public Key
    @param SS the output shared secret
 */
extern void GENERATE_SHARED_SECRET(int group,octet *SK,octet *PK,octet *SS);

/**	@brief Verify a 2048-bit RSA PKCS1.5 signature
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param CERT the input that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool RSA_2048_PKCS15_VERIFY(int sha,octet *CERT,octet *SIG,octet *PUBKEY);

/**	@brief Verify a 4096-bit RSA PKCS1.5 signature
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param CERT the input that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool RSA_4096_PKCS15_VERIFY(int sha,octet *CERT,octet *SIG,octet *PUBKEY);

/**	@brief Verify a 2048-bit RSA PSS RSAE signature
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param MESS the input that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool RSA_2048_PSS_RSAE_VERIFY(int sha,octet *MESS,octet *SIG,octet *PUBKEY);

/**	@brief Verify a 4096-bit RSA PSS RSAE signature
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param MESS the input that was signed
    @param SIG the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool RSA_4096_PSS_RSAE_VERIFY(int sha,octet *MESS,octet *SIG,octet *PUBKEY);

/**	@brief Verify an ECDSA signature on curve SECP256R1
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param CERT the input that was signed
    @param R is first part of the input signature
    @param S is second part of the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool SECP256R1_ECDSA_VERIFY(int sha,octet *CERT,octet *R,octet *S,octet *PUBKEY);

/**	@brief Verify an ECDSA signature on curve SECP384R1
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param CERT the input that was signed
    @param R is first part of the input signature
    @param S is second part of the input signature
    @param PUBKEY the public key used to verify the signature
    @return true if signature is valid, else false
 */
extern bool SECP384R1_ECDSA_VERIFY(int sha,octet *CERT,octet *R,octet *S,octet *PUBKEY);

/**	@brief Create ECDSA signature using curve SECP256R1
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param RNG a random number generator
    @param KEY the private signing key
    @param MESS is the message to be signed
    @param R is first part of the output signature
    @param S is second part of the output signature
 */
extern void SECP256R1_ECDSA_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *R,octet *S);

/**	@brief Create ECDSA signature using curve SECP384R1
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param RNG a random number generator
    @param KEY the private signing key
    @param MESS is the message to be signed
    @param R is first part of the output signature
    @param S is second part of the output signature
 */
void SECP384R1_ECDSA_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *R,octet *S);

/**	@brief Create RSA-2048 PSS-RSAE signature 
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param RNG a random number generator
    @param KEY the private signing key
    @param MESS is the message to be signed
    @param SIG is the output signature
 */
extern void RSA_2048_PSS_RSAE_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *SIG);

/**	@brief Create RSA-4096 PSS-RSAE signature 
 *
    @param sha the SHA2 algorithm (32/48/64)
    @param RNG a random number generator
    @param KEY the private signing key
    @param MESS is the message to be signed
    @param SIG is the output signature
 */
extern void RSA_4096_PSS_RSAE_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *SIG);

#endif