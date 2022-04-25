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


//#ifdef TLS_ARDUINO
//#define POPULAR_ROOT_CERTS        /**< Define this to limit root CAs to most popular only */
//#endif

// THESE ARE IMPORTANT USER DEFINED SETTINGS ***********************************
#define VERBOSITY IO_PROTOCOL     /**< Set to level of output information desired - see above */
#define THIS_YEAR 2022            /**< Set to this year - crudely used to deprecate old certificates */
#define HAVE_A_CLIENT_CERT        /**< Indicate willingness to authenticate with a cert plus signing key */
// Supported protocols    
#define TLS_APPLICATION_PROTOCOL (char *)("http/1.1") /**< Support ALPN protocol */
#define ALLOW_SELF_SIGNED		  /**< allow self-signed server cert */

// Note that the IOBUFF is quite large, and therefore maybe better taken from the heap
// on systems with a shallow stack. Define this to use the heap.

#define IOBUFF_FROM_HEAP          /**< Get main IO buffer from heap, else stack */

// comment out if no max record size. In practise TLS1.3 doesn't seem to support this record_size_limit extension, so use with caution
// #define MAX_RECORD 1024     /**< Maximum record size client is willing to receive - should be less than TLS_MAX_IO_SIZE below */
// Note that if this is not used, max_fragment_size extension is tried instead, see TLS_MAX_FRAG below
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
#define TLS_MAX_ROOT_CERT_SIZE 2048      /**< I checked - current max for root CAs is 2016 */
#define TLS_MAX_ROOT_CERT_B64 2800       /**< In base64 - current max for root CAs is 2688 */
#define TLS_MAX_CERT_SIZE 2048         /**< Max client private key/cert */
#define TLS_MAX_CERT_B64 2800          /**< In base64 - Max client private key/cert */
#define TLS_MAX_HELLO 256         /**< Max client hello size (less extensions) */
#define TLS_MAX_EXT_LABEL 256            /**< Max external psk label size */

#define TLS_MAX_TICKET_SIZE 2048         /**< maximum resumption ticket size */
#define TLS_MAX_EXTENSIONS 2048          /**< Max extensions size */

#ifdef IOBUFF_FROM_HEAP
#define TLS_MAX_IO_SIZE (16384+256)      /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
#else
#define TLS_MAX_IO_SIZE (8192+256)       /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */
#endif

// Max Frag length must be less than TLS_MAX_IO_SIZE
#define TLS_MAX_FRAG 4					/**< Max Fragment length desired - 1 for 512, 2 for 1024, 3 for 2048, 4 for 4096, 0 for 16384 */
#define TLS_MAX_SERVER_PUB_KEY 512      /**< Max Server Public Key size */
#define TLS_MAX_SIGNATURE_SIZE 512      /**< Max digital signature size in bytes  */
#define TLS_MAX_PUB_KEY_SIZE 136        /**< Max key exchange public key size in bytes */
#define TLS_MAX_SHARED_SECRET_SIZE 66	/**< Max key exchange Shared secret size */
#define TLS_MAX_SECRET_KEY_SIZE 64      /**< Max key exchange private key size in bytes */
#define TLS_MAX_ECC_FIELD 66            /**< Max ECC field size in bytes */
#define TLS_MAX_IV_SIZE 12                  /**< Max IV size in bytes */
#define TLS_MAX_TAG_SIZE 16                 /**< Max HMAC tag length in bytes */    
#define TLS_MAX_COOKIE 128              /**< Max Cookie size */    

#define TLS_MAX_SERVER_NAME 128         /**< Max server name size in bytes */
#define TLS_MAX_SUPPORTED_GROUPS 5      /**< Max number of supported crypto groups */
#define TLS_MAX_SUPPORTED_SIGS 16       /**< Max number of supported signature schemes */    
#define TLS_MAX_PSK_MODES 2             /**< Max preshared key modes */
#define TLS_MAX_CIPHER_SUITES 5         /**< Max number of supported cipher suites */

#define TLS_MAX_PLAIN_FRAG 16384		/**< Max Plaintext Fragment size */
#define TLS_MAX_CIPHER_FRAG (16384+256) /**< Max Ciphertext Fragment size */

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

// Signature algorithms for TLS1.3 and Certs that we can handle 
#define ECDSA_SECP256R1_SHA256 0x0403   /**< Supported ECDSA Signature algorithm */ 
#define ECDSA_SECP384R1_SHA384 0x0503   /**< Supported ECDSA Signature algorithm */
#define RSA_PSS_RSAE_SHA256 0x0804      /**< Supported RSA Signature algorithm */ 
#define RSA_PSS_RSAE_SHA384 0x0805      /**< Supported RSA Signature algorithm */
#define RSA_PSS_RSAE_SHA512 0x0806      /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA256 0x0401         /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA384 0x0501         /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA512 0x0601         /**< Supported RSA Signature algorithm */
#define ED25519 0x0807                  /**< Ed25519 EdDSA Signature algorithm */

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

// Extensions 
#define SERVER_NAME 0x0000              /**< Server Name extension */
#define SUPPORTED_GROUPS 0x000a         /**< Supported Group extension */
#define SIG_ALGS 0x000d                 /**< Signature algorithms extension */
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
#define BAD_MESSAGE -23                 /**< Badly formed message */

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
#define CLOSE_NOTIFY 0x00               /**< Orderly shut down of connection */

#define LOG_OUTPUT_TRUNCATION 2048       /**< Output Hex digits before truncation */

#define TLS13_DISCONNECTED 0
#define TLS13_CONNECTED 1

// protocol returns..
#define TLS_FAILURE 0
#define TLS_SUCCESS 1
#define TLS_RESUMPTION_REQUIRED 2
#define TLS_EARLY_DATA_ACCEPTED 3

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
    bool active;
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
    char nonce[TLS_MAX_KEY];            /**< 32-byte nonce */
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
    char hostname[TLS_MAX_SERVER_NAME];     /**< Server name for connection */
    int cipher_suite;       /**< agreed cipher suite */
    int favourite_group;    /**< favourite key exchange group - may be changed on handshake retry */
    crypto K_send;          /**< Sending Key */
    crypto K_recv;          /**< Receiving Key */
    octad RMS;              /**< Resumption Master Secret */
    char rms[TLS_MAX_HASH];
    octad STS;              /**< Server Traffic secret */
    char sts[TLS_MAX_HASH];
    octad CTS;              /**< Client Traffic secret */
    char cts[TLS_MAX_HASH];
    octad IO;               /**< Main IO buffer for this connection */
#ifndef IOBUFF_FROM_HEAP
    char io[TLS_MAX_IO_SIZE];
#endif
    unihash tlshash;        /**< Transcript hash recorder */
    ticket T;               /**< resumption ticket */
} TLS_session;


#endif
