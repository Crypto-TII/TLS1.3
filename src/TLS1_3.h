/**
 * @file tls1_3.h
 * @author Mike Scott
 * @brief Main TLS 1.3 Header File for constants and structures
 *
 */ 

#ifndef TLS1_3_H
#define TLS1_3_H

#include "core.h"

#define IO_NONE 0           /**< Run silently */
#define IO_APPLICATION 1    /**< just print application traffic */
#define IO_PROTOCOL 2       /**< print protocol progress + application traffic */
#define IO_DEBUG 3          /**< print lots of debug information + protocol progress + application traffic */
#define IO_WIRE 4           /**< print lots of debug information + protocol progress + application traffic + bytes on the wire */

// THESE ARE IMPORTANT SETTINGS 
//#define POPULAR_ROOT_CERTS      /**< Define this to limit root CAs to most popular only */
#define VERBOSITY IO_PROTOCOL     /**< Set to level of output information desired - see above */
#define THIS_YEAR 2021          /**< Set to this year - crudely used to deprecate old certificates */
#define HAVE_A_CLIENT_CERT      /**< Indicate willingness to authenticate with a cert plus signing key */

// Some maximum sizes for stack allocated memory. Handshake will fail if these sizes are exceeded! 

#define TLS_MAX_HASH 64         /**< Maximum hash output length in bytes */
#define TLS_MAX_KEY 32          /**< Maximum key length in bytes */
#define TLS_X509_MAX_FIELD 256           /**< Maximum X.509 field size */
#define TLS_MAX_ROOT_CERT_SIZE 2048      /**< I checked - current max for root CAs is 2016 */
#define TLS_MAX_ROOT_CERT_B64 2800       /**< In base64 - current max for root CAs is 2688 */
#define TLS_MAX_MYCERT_SIZE 2048         /**< Max client private key/cert */
#define TLS_MAX_MYCERT_B64 2800          /**< In base64 - Max client private key/cert */
#define TLS_MAX_TICKET_SIZE 2048         /**< maximum resumption ticket size */
#define TLS_MAX_CLIENT_HELLO 256         /**< Max client hello size (less extensions) */
#define TLS_MAX_EXTENSIONS 2048          /**< Max extensions size */
#define TLS_MAX_IO_SIZE 8192             /**< Maximum Input/Output buffer size. We will want to reduce this as much as possible! But must be large enough to take full certificate chain */

#define TLS_MAX_SIGNATURE_SIZE 512      /**< Max digital signature size in bytes  */
#define TLS_MAX_PUB_KEY_SIZE 512        /**< Max public key size in bytes */
#define TLS_MAX_SECRET_KEY_SIZE 512     /**< Max private key size in bytes */
#define TLS_MAX_ECC_FIELD 66            /**< Max ECC field size in bytes */
#define TLS_IV_SIZE 12                  /**< Max IV size in bytes */
#define TLS_TAG_SIZE 16                 /**< Max HMAC tag length in bytes */    
#define TLS_MAX_COOKIE 128              /**< Max Cookie size */    

#define TLS_MAX_SERVER_NAME 128         /**< Max server name size in bytes */
#define TLS_MAX_SUPPORTED_GROUPS 5      /**< Max number of supported crypto groups */
#define TLS_MAX_SUPPORTED_SIGS 16       /**< Max number of supported signature schemes */    
#define TLS_MAX_PSK_MODES 2             /**< Max preshared key modes */
#define TLS_MAX_CIPHER_SUITES 5         /**< Max number of supported cipher suites */

// Cipher Suites 
#define TLS_AES_128_GCM_SHA256 0x1301   /**< AES128/SHA256/GCM cipher suite - this is only one which MUST be implemented */
#define TLS_AES_256_GCM_SHA384 0x1302   /**< AES256/SHA384/GCM cipher suite */
#define TLS_CHACHA20_POLY1305_SHA256 0x1303 /**< CHACHA20/SHA256/POLY1305 cipher suite */

// Supported key exchange groups 
#define X25519 0x001d                   /**< X25519 elliptic curve key exchange */
#define SECP256R1 0x0017                /**< NIST SECP256R1 elliptic curve key exchange */
#define SECP384R1 0x0018                /**< NIST SECP384R1 elliptic curve key exchange */

// Supported signature algorithms for TLS1.3 and Certs that we can handle 
#define ECDSA_SECP256R1_SHA256 0x0403   /**< Supported ECDSA Signature algorithm */ 
#define RSA_PSS_RSAE_SHA256 0x0804      /**< Supported RSA Signature algorithm */ 
#define RSA_PKCS1_SHA256 0x0401         /**< Supported RSA Signature algorithm */
#define ECDSA_SECP384R1_SHA384 0x0503   /**< Supported ECDSA Signature algorithm */
#define RSA_PSS_RSAE_SHA384 0x0805      /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA384 0x0501         /**< Supported RSA Signature algorithm */
#define RSA_PSS_RSAE_SHA512 0x0806      /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA512 0x0601         /**< Supported RSA Signature algorithm */
#define RSA_PKCS1_SHA1 0x0201           /**< Supported (but deprecated!) RSA Signature algorithm */

// pre-shared Key (PSK) modes 
#define PSKOK 0x00                      /**< Preshared Key only mode */
#define PSKWECDHE 0x01                  /**< Preshared Key with Diffie-Hellman key exchange mode */

// TLS versions 
#define TLS1_0 0x0301                   /**< TLS 1.0 version */
#define TLS1_2 0x0303                   /**< TLS 1.2 version */
#define TLS1_3 0x0304                   /**< TLS 1.3 version */

// Extensions 
#define SERVER_NAME 0x0000              /**< Server Name extension */
#define SUPPORTED_GROUPS 0x000a         /**< Supported Group extension */
#define SIG_ALGS 0x000d                 /**< Signature algorithms extension */
#define SIG_ALGS_CERT 0x0032            /**< Signatre algorithms Certificate extension */
#define KEY_SHARE 0x0033                /**< Key Share extension */
#define PSK_MODE 0x002d                 /**< Preshared key mode extension */
#define PRESHARED_KEY 0x0029            /**< Preshared key extension */
#define TLS_VER 0x002b                  /**< TLS version extension */
#define COOKIE 0x002c                   /**< Cookie extension */
#define EARLY_DATA 0x002a               /**< Early Data extension */
#define MAX_FRAG_LENGTH 0x0001          /**< max fragmentation length extension */
#define PADDING 0x0015                  /**< Padding extension */

// record types 
#define HSHAKE 0x16                     /**< Handshake record */
#define APPLICATION 0x17                /**< Application record */
#define ALERT 0x15                      /**< Alert record */
#define CHANGE_CIPHER 0x14              /**< Change Cipher record */
// pseudo-types
#define TIME_OUT 0x01                   /**< Time-out  */
#define HANDSHAKE_RETRY 0x02            /**< Handshake retry */
#define STRANGE_EXTENSION 0x03          /**< Strange extension */

// message types 
#define CLIENT_HELLO 0x01               /**< Client Hello message */ 
#define SERVER_HELLO 0x02               /**< Server Hello message */ 
#define CERTIFICATE 0x0b                /**< Certificate message */ 
#define CERT_REQUEST 0x0d               /**< Certificate Request */
#define CERT_VERIFY 0x0f                /**< Certificate Verify message */ 
#define FINISHED 0x14                   /**< Handshae Finished message */
#define ENCRYPTED_EXTENSIONS 0x08       /**< Encrypted Extensions message */ 
#define TICKET 0x04                     /**< Ticket message */ 
#define KEY_UPDATE 0x18                 /**< Key Update message */
#define MESSAGE_HASH 0xFE               /**< Special synthetic message hash message */    
#define END_OF_EARLY_DATA 0x05          /**< End of Early Data message */    

// Causes of server error - which should generate an alert 
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

// alerts 
#define ILLEGAL_PARAMETER 0x2F          /**< Illegal parameter alert from Server */
#define UNEXPECTED_MESSAGE 0x0A         /**< Unexpected message alert from Server */
#define DECRYPT_ERROR 0x33              /**< Decryption error alert from Server */
#define BAD_CERTIFICATE 0x2A            /**< Bad certificate alert from Server */
#define UNSUPPORTED_EXTENSION 0x6E      /**< Unsupported extension alert from Server */

using namespace core;

/**
 * @brief function return structure */
typedef struct 
{
    unsign32 val;    /**< return value */
    int err;         /**< error return */   
} ret;

/**
 * @brief crypto context structure */
typedef struct
{
    char k[TLS_MAX_KEY];    /**< AEAD cryptographic Key bytes */
    char iv[12];            /**< AEAD cryptographic IV bytes */
    octet K;                /**< Key as octet */
    octet IV;               /**< IV as octet */
    unsign32 record;        /**< current record number - to be incremented */
} crypto;

/**
 * @brief ticket context structure */
typedef struct 
{
    char tick[TLS_MAX_TICKET_SIZE];     /**< Ticket bytes */
    char nonce[32];                     /**< 32-byte nonce */
    octet TICK;                         /**< Ticket as octet */
    octet NONCE;                        /**< Nonce as octet */
    int lifetime;                       /**< ticket lifetime */
    unsign32 age_obfuscator;            /**< ticket age obfuscator */
    unsign32 max_early_data;            /**< Maximum early data allowed for this ticket */
    unsign32 birth;                     /**< Birth time of this ticket */    
} ticket;

/**
 * @brief Cryptographic capabilities of the client */
typedef struct 
{
    int nsg;                            /**< Number of supported groups */
    int supportedGroups[TLS_MAX_SUPPORTED_GROUPS];  /**< Supported groups */
    int nsc;                            /**< Number of supported cipher suites */
    int ciphers[TLS_MAX_CIPHER_SUITES]; /**< Supported cipher suites */
    int nsa;                            /**< Number of supported signature algorithms for TLS 1.3 */
    int sigAlgs[TLS_MAX_SUPPORTED_SIGS];    /**< Supported signature algorithms for TLS1.3 */
    int nsac;                               /**< Number of supported signature algorithms for Certificates */
    int sigAlgsCert[TLS_MAX_SUPPORTED_SIGS]; /**< Supported signature algorithms for Certicates */
} capabilities;

#endif

