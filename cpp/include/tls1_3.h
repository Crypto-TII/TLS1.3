/**
 * @file tls1_3.h
 * @author Mike Scott
 * @brief Main TLS 1.3 Header File for constants and structures
 *
 */ 

#ifndef TLS1_3_H
#define TLS1_3_H

#include <stdint.h>
#include "tls_octads.h"
#include "tls_sockets.h"

typedef uint8_t byte;           /**< 8-bit unsigned integer */
typedef int8_t sign8 ;			/**< 8-bit signed integer */
typedef int16_t sign16;			/**< 16-bit signed integer */
typedef int32_t sign32;			/**< 32-bit signed integer */
typedef int64_t sign64;			/**< 64-bit signed integer */
typedef uint32_t unsign32 ;		/**< 32-bit unsigned integer */
typedef uint64_t unsign64;		/**< 64-bit unsigned integer */

// Terminal Output
#define IO_NONE 0           /**< Run silently */
#define IO_APPLICATION 1    /**< just print application traffic */
#define IO_PROTOCOL 2       /**< print protocol progress + application traffic */
#define IO_DEBUG 3          /**< print lots of debug information + protocol progress + application progress */
#define IO_WIRE 4           /**< print lots of debug information + protocol progress + application progress + bytes on the wire */

// // Supported CRYPTO_SETTINGs
#define TINY_ECC 0          /**< ECC keys only */
#define TYPICAL 1           /**< Mixture of RSA and ECC - for use with most standard web servers */
#define POST_QUANTUM 2      /**< Post quantum (Dilithium+Kyber?) */   
#define HYBRID 3            /**< Hybrid, Kyber/Dilithium + X25519 */

// Client Certificate Chain + Key
#define NOCERT 0  /**< Don't have a Client Cert */
#define RSA_SS 1  /**< self signed RSA cert */
#define ECC_SS 2  /**< self signed ECC cert */
#define DLT_SS 3  /**< self signed Dilithium cert */
#define HYB_SS 6  /**< self signed Hybrid cert (Dilithium+ECC) */
#define HW_1 4    /**< RP2040 1 Hardware cert */
#define HW_2 5    /**< RP2040 2 Hardware cert */

// THESE ARE IMPORTANT USER DEFINED SETTINGS ***********************************

// Note that favourite group (as used in client hello) is determined by the SAL ordering - see tls_sal.cpp
// If server does not support it, an expensive Handshake Retry will be required
// So best to place a popular group (such as X25519) at top of list in SAL

#define VERBOSITY IO_PROTOCOL     /**< Set to level of output information desired - see above */
#define THIS_YEAR 2023            /**< Set to this year - crudely used to deprecate old certificates */

#define POST_HS_AUTH              /**< Willing to do post handshake authentication */
#define CLIENT_CERT RSA_SS        /**< Indicate capability of authenticating with a cert plus signing key */

#define CRYPTO_SETTING TYPICAL   /**< Determine Cryptography settings */
// Supported protocols    
#define TLS_APPLICATION_PROTOCOL (char *)("http/1.1") /**< Support ALPN protocol */
#define ALLOW_SELF_SIGNED		 /**< allow self-signed server cert */
//#define NO_CERT_CHECKS		 /**< Don't do any checks on server certs - useful for Anvil testing */
#define TRY_EARLY_DATA           /**< Try to send early data on resumptions */

// Note that BUFF, Certificates and crypto keys can be quite large, and therefore maybe better taken from the heap
// on systems with a shallow stack. Define this to use the heap.

//#define SHALLOW_STACK           /**< Get large arrays from heap, else stack */

// comment out if no max record size. In practise TLS1.3 doesn't seem to support this record_size_limit extension, so use with caution
// #define MAX_RECORD 1024     /**< Maximum record size client is willing to receive - should be less than TLS_MAX_IBUFF_SIZE below */
// Note that if this is not used, max_fragment_size extension is tried instead, see TLS_MAX_FRAG below

// define this so that all encrypted records are padded with 0s to full length
// #define PAD_SHORT_RECORDS		/**< Pad short output records */ 

//#define PREFER_RAW_SERVER_PUBLIC_KEY   /**< Would be happy with raw public key from server */
//#define PREFER_RAW_CLIENT_PUBLIC_KEY   /**< Would prefer server to accept raw public key from client */

// may need to undefine this for fuzzing 
#define MERGE_MESSAGES                  /**< allow merging of messages into single record */

// *****************************************************************************


// Standard Hash Types

#define TLS_SHA256_T 1           /**< SHA256 hash  */
#define TLS_SHA384_T 2           /**< SHA384 hash  */
#define TLS_SHA512_T 3           /**< SHA512 hash  */

// Some maximum sizes for stack allocated memory. Handshake will fail if these sizes are exceeded! 

#define TLS_MAX_HASH_STATE 768  /**< Maximum memory required to store hash function state */
#define TLS_MAX_HASH 64         /**< Maximum hash output length in bytes */
#define TLS_MAX_KEY 32          /**< Maximum key length in bytes */
#define TLS_X509_MAX_FIELD 256           /**< Maximum X.509 field size */
#define TLS_MAX_EXT_LABEL 256            /**< Max external psk label size */

// Max Frag length must be less than TLS_MAX_IBUFF_SIZE
#define TLS_MAX_FRAG 2					/**< Max Fragment length desired - 1 for 512, 2 for 1024, 3 for 2048, 4 for 4096, 0 for 16384 */

#if CRYPTO_SETTING==TYPICAL
 #define TLS_MAX_IBUFF_SIZE (16384+256)      /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
 #define TLS_MAX_PLAIN_FRAG 16384		 /**< Max Plaintext Fragment size */
 #define TLS_MAX_CIPHER_FRAG (16384+256)  /**< Max Ciphertext Fragment size */

 #define TLS_MAX_CERT_SIZE 2048       /**< I checked - current max for root CAs is 2016 */
 #define TLS_MAX_CERT_B64 2800        /**< In base64 - current max for root CAs is 2688 */
 #define TLS_MAX_HELLO 1024           /**< Max client hello size (less extensions) KEX public key is largest component */

 #define TLS_MAX_SIG_PUB_KEY_SIZE 512        /**< Max signature public key size in bytes		RSA */
 #define TLS_MAX_SIG_SECRET_KEY_SIZE 512     /**< Max signature private key size in bytes       RSA */
 #define TLS_MAX_SIGNATURE_SIZE 512          /**< Max digital signature size in bytes           RSA */
 #define TLS_MAX_KEX_PUB_KEY_SIZE 97         /**< Max key exchange public key size in bytes		ECC */
 #define TLS_MAX_KEX_CIPHERTEXT_SIZE 97      /**< Max key exchange (KEM) ciphertext size        ECC */
 #define TLS_MAX_KEX_SECRET_KEY_SIZE 48      /**< Max key exchange private key size in bytes    ECC */
#endif

#if CRYPTO_SETTING == POST_QUANTUM

 #define TLS_MAX_IBUFF_SIZE (16384+256)      /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
 #define TLS_MAX_PLAIN_FRAG 16384		 /**< Max Plaintext Fragment size */
 #define TLS_MAX_CIPHER_FRAG (16384+256)  /**< Max Ciphertext Fragment size */

 #define TLS_MAX_CERT_SIZE 6144      /**< I checked - current max for root CAs is 2016 - but would be much bigger for Dilithium!*/
 #define TLS_MAX_CERT_B64 8192       /**< In base64 - current max for root CAs is 2688 */
 #define TLS_MAX_HELLO 2048          /**< Max client hello size (less extensions) KEX public key is largest component */

// These all blow up post quantum
 #define TLS_MAX_SIG_PUB_KEY_SIZE 1952        /**< Max signature public key size in bytes     DILITHIUM3 */
 #define TLS_MAX_SIG_SECRET_KEY_SIZE 4000     /**< Max signature private key size in bytes    DILITHIUM3 (maybe includes the public key?) */
 #define TLS_MAX_SIGNATURE_SIZE 3296          /**< Max signature size in bytes                DILITHIUM3 */
 #define TLS_MAX_KEX_PUB_KEY_SIZE 1184        /**< Max key exchange public key size in bytes  KYBER768   */
 #define TLS_MAX_KEX_CIPHERTEXT_SIZE 1088     /**< Max key exchange (KEM) ciphertext size     KYBER768   */
 #define TLS_MAX_KEX_SECRET_KEY_SIZE 2400     /**< Max key exchange private key size in bytes KYBER768   */
#endif

#if CRYPTO_SETTING == HYBRID

 #define TLS_MAX_IBUFF_SIZE (16384+256)      /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
 #define TLS_MAX_PLAIN_FRAG 16384		 /**< Max Plaintext Fragment size */
 #define TLS_MAX_CIPHER_FRAG (16384+256)  /**< Max Ciphertext Fragment size */

 #define TLS_MAX_CERT_SIZE 6144      /**< I checked - current max for root CAs is 2016 - but would be much bigger for Dilithium!*/
 #define TLS_MAX_CERT_B64 8192       /**< In base64 - current max for root CAs is 2688 */
 #define TLS_MAX_HELLO 2048          /**< Max client hello size (less extensions) KEX public key is largest component */

// These all blow up post quantum
 #define TLS_MAX_SIG_PUB_KEY_SIZE 1312+65        /**< Max signature public key size in bytes     DILITHIUM2 + P256 */
 #define TLS_MAX_SIG_SECRET_KEY_SIZE 2528+200     /**< Max signature private key size in bytes    DILITHIUM2 + P256 (maybe includes the public key?) */
 #define TLS_MAX_SIGNATURE_SIZE 2420+100          /**< Max signature size in bytes                DILITHIUM2 + P256 (DER encoding for ECC sig) */
 #define TLS_MAX_KEX_PUB_KEY_SIZE 1184+32        /**< Max key exchange public key size in bytes  KYBER768+X25519   */
 #define TLS_MAX_KEX_CIPHERTEXT_SIZE 1088+32     /**< Max key exchange (KEM) ciphertext size     KYBER768+X25519   */
 #define TLS_MAX_KEX_SECRET_KEY_SIZE 2400+32     /**< Max key exchange private key size in bytes KYBER768+X25519   */
#endif


#if CRYPTO_SETTING==TINY_ECC
 #define TLS_MAX_IBUFF_SIZE (4096+256)      /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
 #define TLS_MAX_PLAIN_FRAG 4096		 /**< Max Plaintext Fragment size */
 #define TLS_MAX_CIPHER_FRAG (4096+256)  /**< Max Ciphertext Fragment size */

 #define TLS_MAX_CERT_SIZE 2048      /**< I checked - current max for root CAs is 2016 */
 #define TLS_MAX_CERT_B64 2800       /**< In base64 - current max for root CAs is 2688 */
 #define TLS_MAX_HELLO 1024          /**< Max client hello size (less extensions) KEX public key is largest component */

 #define TLS_MAX_SIG_PUB_KEY_SIZE 133        /**< Max signature public key size in bytes		ECC */
 #define TLS_MAX_SIG_SECRET_KEY_SIZE 66      /**< Max signature private key size in bytes       ECC */
 #define TLS_MAX_SIGNATURE_SIZE 132          /**< Max signature size in bytes                   ECC */
 #define TLS_MAX_KEX_PUB_KEY_SIZE 97         /**< Max key exchange public key size in bytes		ECC */
 #define TLS_MAX_KEX_CIPHERTEXT_SIZE 97      /**< Max key exchange (KEM) ciphertext size        ECC */
 #define TLS_MAX_KEX_SECRET_KEY_SIZE 48      /**< Max key exchange private key size in bytes    ECC */
#endif

// Certificate size limits
#define TLS_MAX_SERVER_CHAIN_LEN 2             /**< Maximum Server Certificate chain length - omitting root CA */
#define TLS_MAX_SERVER_CHAIN_SIZE (TLS_MAX_SERVER_CHAIN_LEN*TLS_MAX_CERT_SIZE) /**< Maximum Server Certificate chain length in bytes */
#define TLS_MAX_CLIENT_CHAIN_LEN 1             /**< Maximum Client Certificate chain length - one self signed here */
#define TLS_MAX_CLIENT_CHAIN_SIZE (TLS_MAX_CLIENT_CHAIN_LEN*TLS_MAX_CERT_SIZE) /**< Maximum Client Certificate chain length in bytes */

#define TLS_MAX_SHARED_SECRET_SIZE 256	 /**< Max key exchange Shared secret size */

// Both of these are bumped up by PQ IBE and Hybrid
#define TLS_MAX_TICKET_SIZE 4196         /**< maximum resumption ticket size - beware some servers send much bigger tickets! */
#define TLS_MAX_EXTENSIONS 6144          /**< Max extensions size */

#define TLS_MAX_ECC_FIELD 66            /**< Max ECC field size in bytes */
#define TLS_MAX_IV_SIZE 12              /**< Max IV size in bytes */
#define TLS_MAX_TAG_SIZE 16             /**< Max HMAC tag length in bytes */    
#define TLS_MAX_COOKIE 128              /**< Max Cookie size */    

#define TLS_MAX_OUTPUT_RECORD_SIZE 1024   /**< Max output record size */
#define TLS_MAX_OBUFF_SIZE (TLS_MAX_OUTPUT_RECORD_SIZE+TLS_MAX_TAG_SIZE+6) /**< Max output buffer size */

#define TLS_MAX_SERVER_NAME 128         /**< Max server name size in bytes */
#define TLS_MAX_SUPPORTED_GROUPS 10      /**< Max number of supported crypto groups */
#define TLS_MAX_SUPPORTED_SIGS 16       /**< Max number of supported signature schemes */    
#define TLS_MAX_PSK_MODES 2             /**< Max preshared key modes */
#define TLS_MAX_CIPHER_SUITES 5         /**< Max number of supported cipher suites */

// Cipher Suites 
#define TLS_AES_128_GCM_SHA256 0x1301   /**< AES128/SHA256/GCM cipher suite - this is only one which MUST be implemented */
#define TLS_AES_256_GCM_SHA384 0x1302   /**< AES256/SHA384/GCM cipher suite */
#define TLS_CHACHA20_POLY1305_SHA256 0x1303 /**< CHACHA20/SHA256/POLY1305 cipher suite */
#define TLS_AES_128_CCM_SHA256 0x1304   /**< AES/SHA256/CCM cipher suite - optional */
#define TLS_AES_128_CCM_8_SHA256 0x1305 /**< AES/SHA256/CCM 8 cipher suite - optional */

// Key exchange groups 
#define X25519 0x001d                   /**< X25519 elliptic curve key exchange */
#define SECP256R1 0x0017                /**< NIST SECP256R1 elliptic curve key exchange */
#define SECP384R1 0x0018                /**< NIST SECP384R1 elliptic curve key exchange */
#define SECP521R1 0x0019				/**< NIST SECP521R1 elliptic curve key exchange */
#define X448 0x001e						/**< X448 elliptic curve key exchange */
#define KYBER768 0x4242                 /**< Kyber PQ key exchange - NOTE I just made this up! Not generally recognised! */
#define HYBRID_KX 0x421d                /**< Hybrid key exchange, Kyber+X25519 */

// Signature algorithms for TLS1.3 and Certs that we can handle 
#define ECDSA_SECP256R1_SHA256 0x0403   /**< Supported ECDSA Signature algorithm */ 
#define ECDSA_SECP256R1_SHA384 0x0413   /**< Non-standard ECDSA Signature algorithm */ 
#define ECDSA_SECP384R1_SHA384 0x0503   /**< Supported ECDSA Signature algorithm */
#define RSA_PSS_RSAE_SHA256 0x0804      /**< Supported RSA Signature algorithm */ 
#define RSA_PSS_RSAE_SHA384 0x0805      /**< Supported RSA Signature algorithm */
#define RSA_PSS_RSAE_SHA512 0x0806      /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA256 0x0401         /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA384 0x0501         /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA512 0x0601         /**< Supported RSA Signature algorithm */
#define ED25519 0x0807                  /**< Ed25519 EdDSA Signature algorithm */
#define DILITHIUM2 0x0902               /**< Dilithium2 Signature algorithm */
#define DILITHIUM3 0x0903               /**< Dilithium3 Signature algorithm */
#define DILITHIUM2_P256 0x09F2          /**< Dilithium2+SECP256R1 Signature algorithms - this type can be negotiated, but always implemented seperately by SAL */

// pre-shared Key (PSK) modes 
#define PSKOK 0x00                      /**< Preshared Key only mode */
#define PSKWECDHE 0x01                  /**< Preshared Key with Diffie-Hellman key exchange mode */

// ticket origin
#define TLS_FULL_HANDSHAKE  1           /**< Came from Full Handshake */
#define TLS_EXTERNAL_PSK  2             /**< External Pre-Shared Key */

// TLS versions 
#define TLS1_0 0x0301                   /**< TLS 1.0 version */
#define TLS1_2 0x0303                   /**< TLS 1.2 version */
#define TLS1_3 0x0304                   /**< TLS 1.3 version */

#define TLS13_UPDATE_NOT_REQUESTED 0			/**< Updating my keys */
#define TLS13_UPDATE_REQUESTED 1				/**< Updating my keys and telling you to update yours */

// Extensions 
#define SERVER_NAME 0x0000              /**< Server Name extension */
#define SUPPORTED_GROUPS 0x000a         /**< Supported Group extension */
#define SIG_ALGS 0x000d                 /**< Signature algorithms extension */
#define POST_HANDSHAKE_AUTH 0x0031      /**< Post Handshake Authentication */
#define SIG_ALGS_CERT 0x0032            /**< Signature algorithms Certificate extension */
#define KEY_SHARE 0x0033                /**< Key Share extension */
#define PSK_MODE 0x002d                 /**< Preshared key mode extension */
#define PRESHARED_KEY 0x0029            /**< Preshared key extension */
#define TLS_VER 0x002b                  /**< TLS version extension */
#define COOKIE 0x002c                   /**< Cookie extension */
#define EARLY_DATA 0x002a               /**< Early Data extension */
#define MAX_FRAG_LENGTH 0x0001          /**< max fragmentation length extension */
#define PADDING 0x0015                  /**< Padding extension */
#define APP_PROTOCOL 0x0010             /**< Application Layer Protocol Negotiation (ALPN) */
#define RECORD_SIZE_LIMIT 0x001c        /**< Record Size Limit */
#define CLIENT_CERT_TYPE 0x0013         /**< Client Certificate type */
#define SERVER_CERT_TYPE 0x0014         /**< Server Certificate type */


// record types 
#define HSHAKE 0x16                     /**< Handshake record */
#define APPLICATION 0x17                /**< Application record */
#define ALERT 0x15                      /**< Alert record */
#define CHANGE_CIPHER 0x14              /**< Change Cipher record */
// pseudo record types
#define TIMED_OUT 0x01                  /**< Time-out  */

// message types 
#define CLIENT_HELLO 0x01               /**< Client Hello message */ 
#define SERVER_HELLO 0x02               /**< Server Hello message */ 
#define CERTIFICATE 0x0b                /**< Certificate message */ 
#define CERT_REQUEST 0x0d               /**< Certificate Request */
#define CERT_VERIFY 0x0f                /**< Certificate Verify message */ 
#define FINISHED 0x14                   /**< Handshake Finished message */
#define ENCRYPTED_EXTENSIONS 0x08       /**< Encrypted Extensions message */ 
#define TICKET 0x04                     /**< Ticket message */ 
#define KEY_UPDATE 0x18                 /**< Key Update message */
#define MESSAGE_HASH 0xFE               /**< Special synthetic message hash message */    
#define END_OF_EARLY_DATA 0x05          /**< End of Early Data message */   
// pseudo message types
#define HANDSHAKE_RETRY 0x102           /**< Handshake retry */

// Causes of server error - which should generate a client alert 
#define NOT_TLS1_3 -2                   /**< Wrong version error, not TLS1.3 */
#define BAD_CERT_CHAIN -3               /**< Bad Certificate Chain error */
#define ID_MISMATCH -4                  /**< Session ID mismatch error */
#define UNRECOGNIZED_EXT -5             /**< Unrecognised extension error */
#define BAD_HELLO -6                    /**< badly formed Hello message error */
#define WRONG_MESSAGE -7                /**< Message out-of-order error */
#define MISSING_REQUEST_CONTEXT -8      /**< Request context missing error */
#define AUTHENTICATION_FAILURE -9       /**< Authentication error - AEAD Tag incorrect */
#define BAD_RECORD -10                  /**< Badly formed Record received */
#define BAD_TICKET -11                  /**< Badly formed Ticket received */
#define NOT_EXPECTED -12                /**< Received ack for something not requested */
#define CA_NOT_FOUND -13                /**< Certificate Authority not found */
#define CERT_OUTOFDATE -14              /**< Certificate Expired */
#define MEM_OVERFLOW -15                /**< Memory Overflow */
#define FORBIDDEN_EXTENSION -16			/**< Forbidden Encrypted Extension */
#define MAX_EXCEEDED -17				/**< Maximum record size exceeded */
#define EMPTY_CERT_CHAIN -18            /**< Empty Certificate Message */
#define SELF_SIGNED_CERT -20			/**< Self signed certificate */
#define ERROR_ALERT_RECEIVED -22        /**< Alert has been received */
#define BAD_MESSAGE -23                 /**< Badly formed message */
#define CERT_VERIFY_FAIL -24            /**< Certificate Verification failure */
#define BAD_HANDSHAKE -26               /**< Could not agree */
#define BAD_REQUEST_UPDATE -27			/**< Bad Request Update value */
#define CLOSURE_ALERT_RECEIVED -28      /**< Alert has been received */
#define MISSING_EXTENSIONS -30          /**< Some mandatory extensions are missing */
// client alerts 
#define ILLEGAL_PARAMETER 0x2F          /**< Illegal parameter alert */
#define UNEXPECTED_MESSAGE 0x0A         /**< Unexpected message alert */
#define DECRYPT_ERROR 0x33              /**< Decryption error alert */
#define BAD_CERTIFICATE 0x2A            /**< Bad certificate alert */
#define UNSUPPORTED_EXTENSION 0x6E      /**< Unsupported extension alert */
#define UNKNOWN_CA 0x30                 /**< Unrecognised Certificate Authority */
#define CERTIFICATE_EXPIRED 0x2D        /**< Certificate Expired */
#define PROTOCOL_VERSION 0x46           /**< Wrong TLS version */
#define DECODE_ERROR 0x32               /**< Decode error alert */
#define RECORD_OVERFLOW 0x16            /**< Record Overflow */
#define BAD_RECORD_MAC 0x14				/**< Bad Record Mac */
#define HANDSHAKE_FAILURE 0x28			/**< Could not agree */
#define CLOSE_NOTIFY 0x00               /**< Orderly shut down of connection */
#define MISSING_EXTENSION 0x6D;         /**< Missing extension */

#define LOG_OUTPUT_TRUNCATION 256       /**< Output Hex digits before truncation */

#define TLS13_DISCONNECTED 0            /**< TLS1.3 Connection is broken */
#define TLS13_CONNECTED 1               /**< TLS1.3 Connection is made */ 
#define TLS13_HANDSHAKING 2				/**< TLS1.3 is handshaking */

// protocol returns..
#define TLS_FAILURE 0                   /**< Failed to cmake TLS1.3 connection */
#define TLS_SUCCESS 1                   /**< Succeeded in making TLS1.3 connection */ 
#define TLS_RESUMPTION_REQUIRED 2       /**< Connection succeeded, but handshake retry was needed */
#define TLS_EARLY_DATA_ACCEPTED 3       /**< Connection succeeded, and early data was accepted */

// PSK modes
#define PSK_NOT 0           /**< No PSK */
#define PSK_KEY 1           /**< Using PSK from database */
#define PSK_IBE 2           /**< Using IBE based PSK */

// Certificate types
#define X509_CERT 0			/**< X509 Certificate-based authentication */
#define RAW_PUBLIC_KEY 2	/**< Raw Public Key based authentication */

/**
 * @brief function return structure */
typedef struct 
{
    unsign32 val;    /**< return value */
    int err;         /**< error return */   
} ret;

/**
 * @brief server encrypted extensions expectations/responses */
typedef struct 
{
    bool early_data;    /**< true if early data accepted */
    bool alpn;          /**< true if ALPN accepted */
    bool server_name;   /**< true if server name accepted */
    bool max_frag_length;   /**< true if max frag length respected */
} ee_status;

/**
 * @brief crypto context structure */
typedef struct
{
    bool active;            /**< Indicates if encryption has been activated */
    char k[TLS_MAX_KEY];    /**< AEAD cryptographic Key bytes */
    char iv[12];            /**< AEAD cryptographic IV bytes */
    octad K;                /**< Key as octad */
    octad IV;               /**< IV as octad */
    unsign32 record;        /**< current record number - to be incremented */
    int suite;              /**< Cipher Suite */
	int taglen;				/**< Tag Length */
} crypto;

/**
 * @brief ticket context structure */
typedef struct 
{
    bool valid;                         /**< Is ticket valid? */
    char tick[TLS_MAX_TICKET_SIZE];     /**< Ticket bytes */
    char nonce[256];                    /**< nonce */
    char psk[TLS_MAX_HASH];             /**< pre-shared key */
    octad TICK;                         /**< Ticket or external PSK label as octad */
    octad NONCE;                        /**< Nonce as octad */
    octad PSK;                          /**< PSK as octad */
    unsign32 age_obfuscator;            /**< ticket age obfuscator - 0 for external PSK */
    unsign32 max_early_data;            /**< Maximum early data allowed for this ticket */
    unsign32 birth;                     /**< Birth time of this ticket */ 
    int lifetime;                       /**< ticket lifetime */        
    int cipher_suite;                   /**< Cipher suite used */
    int favourite_group;                /**< the server's favourite group */
    int origin;                         /**< Origin of initial handshake - Full or PSK? */
} ticket;

/**
 * @brief Universal Hash Function */
typedef struct 
{
    char state[TLS_MAX_HASH_STATE];   /**< hash function state */
    int htype;                        /**< The hash type (typically SHA256) */
} unihash;

/**
 * @brief TLS1.3 session state */
typedef struct 
{
    int status;             /**< Connection status */
	int max_record;         /**< max record size I should send */
    Socket *sockptr;        /**< Pointer to socket */
	char id[32];            /**< Session ID */
    char hostname[TLS_MAX_SERVER_NAME];     /**< Server name for connection */
    int cipher_suite;       /**< agreed cipher suite */
    int favourite_group;    /**< favourite key exchange group - may be changed on handshake retry */
	int server_cert_type;   /**< server certificate type */
	int client_cert_type;   /**< client certificate type */
    crypto K_send;          /**< Sending Key */
    crypto K_recv;          /**< Receiving Key */
    octad HS;               /**< Handshake secret */
    char hs[TLS_MAX_HASH];  /**< Handshake secret data */
    octad RMS;              /**< Resumption Master Secret */
    char rms[TLS_MAX_HASH]; /**< Resumption Master Secret data */
    octad STS;              /**< Server Traffic secret */
    char sts[TLS_MAX_HASH]; /**< Server Traffic secret data */
    octad CTS;              /**< Client Traffic secret */
    char cts[TLS_MAX_HASH]; /**< Client Traffic secret data */
    octad CTX;              /**< Certificate Request Context */
    char ctx[TLS_MAX_HASH];	/**< Certificate Request Context data */
    octad IBUFF;               /**< Main input buffer for this connection */
	octad OBUFF;			/**< output buffer for this connection */
#ifndef SHALLOW_STACK
    char ibuff[TLS_MAX_IBUFF_SIZE]; /**< Byte array for main input buffer for this connection */
	char obuff[TLS_MAX_OBUFF_SIZE]; /**< output buffer for this connection */
#endif
    int ptr;                /**< pointer into IBUFF buffer */
    unihash tlshash;        /**< Transcript hash recorder */
    ticket T;               /**< resumption ticket */
} TLS_session;

// IBUFF buffer
// xxxxxxxxxxxxxxxxxxxxxxxxxxxyyyyyyyyyyyyyyyyyyyyyyyyyyy
// -------------ptr---------->----------IBUFF.len------->
//
// when ptr becomes equal to IBUFF.len, pull in another record (and maybe decrypt it)

#endif
