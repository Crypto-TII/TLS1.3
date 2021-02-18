// main header file for constants and structures 

#ifndef TLS1_3_H
#define TLS1_3_H

#include "core.h"

#define IO_NONE 0     // Run silently
#define IO_APPLICATION 1    // just print application traffic
#define IO_PROTOCOL 2       // print protocol progress + application traffic
#define IO_DEBUG 3    // print lots of debug information + protocol progress + application traffic
#define IO_WIRE 4    // print lots of debug information + protocol progress + application traffic + bytes on the wire

// THESE ARE IMPORTANT SETTINGS
#define POPULAR_ROOT_CERTS      // Define this to limit root CAs to most popular only
#define VERBOSITY IO_PROTOCOL   // Set to level of output information desired - see above
#define THIS_YEAR 2021

// Some maximum sizes for stack allocated memory
// Handshake will fail if these sizes are exceeded!
#define TLS_MAX_HASH 64
#define TLS_MAX_KEY 32
#define TLS_X509_MAX_FIELD 256           // Maximum X.509 field size
#define TLS_MAX_ROOT_CERT_SIZE 2048      // I checked - current max for root CAs is 2016
#define TLS_MAX_ROOT_CERT_B64 2800       // In base64 - current max for root CAs is 2688
#define TLS_MAX_TICKET_SIZE 512
#define TLS_MAX_CLIENT_HELLO 256         // Max size (less extensions)
#define TLS_MAX_EXTENSIONS 512
#define TLS_MAX_IO_SIZE 6144 //4096 //8192// 6144 //16384? We will want to reduce this as much as possible! But must be large enough to take full certificate chain

#define TLS_MAX_SIGNATURE_SIZE 512
#define TLS_MAX_PUB_KEY_SIZE 512
#define TLS_MAX_SECRET_KEY_SIZE 512
#define TLS_MAX_ECC_FIELD 66
#define TLS_IV_SIZE 12
#define TLS_TAG_SIZE 16
#define TLS_MAX_COOKIE 128

#define TLS_MAX_SERVER_NAME 128
#define TLS_MAX_SUPPORTED_GROUPS 5
#define TLS_MAX_SUPPORTED_SIGS 12
#define TLS_MAX_KEY_SHARES 3
#define TLS_MAX_PSK_MODES 2
#define TLS_MAX_CIPHER_SUITES 5

// Cipher Suites
#define TLS_AES_128_GCM_SHA256 0x1301  // this is only one which MUST be implemented
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

// Supported key exchange groups
#define X25519 0x001d
#define SECP256R1 0x0017
#define SECP384R1 0x0018

// Supported signature algorithms for Certs that we can handle 
#define ECDSA_SECP256R1_SHA256 0x0403
#define RSA_PSS_RSAE_SHA256 0x0804
#define RSA_PKCS1_SHA256 0x0401
#define ECDSA_SECP384R1_SHA384 0x0503
#define RSA_PSS_RSAE_SHA384 0x0805
#define RSA_PKCS1_SHA384 0x0501
#define RSA_PSS_RSAE_SHA512 0x0806
#define RSA_PKCS1_SHA512 0x0601
#define RSA_PKCS1_SHA1 0x0201

//pre-shared Key (PSK) modes
#define PSKOK 0x00
#define PSKWECDHE 0x01

// TLS versions
#define TLS1_0 0x0301
#define TLS1_2 0x0303
#define TLS1_3 0x0304

// Extensions
#define SERVER_NAME 0x0000
#define SUPPORTED_GROUPS 0x000a
#define SIG_ALGS 0x000d
#define KEY_SHARE 0x0033
#define PSK_MODE 0x002d
#define PRESHARED_KEY 0x0029
#define TLS_VER 0x002b
#define COOKIE 0x002c
#define EARLY_DATA 0x002a
#define MAX_FRAG_LENGTH 0x0001

// record types
#define HSHAKE 0x16
#define APPLICATION 0x17
#define ALERT 0x15
#define CHANGE_CIPHER 0x14
// pseudo-types
#define TIME_OUT 0x01
#define HANDSHAKE_RETRY 0x02
#define STRANGE_EXTENSION 0x03

// message types
#define CLIENT_HELLO 0x01
#define SERVER_HELLO 0x02
#define CERTIFICATE 0x0b
#define CERT_VERIFY 0x0f
#define FINISHED 0x14
#define ENCRYPTED_EXTENSIONS 0x08
#define TICKET 0x04
#define KEY_UPDATE 0x18
#define MESSAGE_HASH 0xFE
#define END_OF_EARLY_DATA 0x05

// Causes of server error - which should generate an alert
#define NOT_TLS1_3 -2
#define BAD_CERT_CHAIN -3
#define ID_MISMATCH -4
#define UNRECOGNIZED_EXT -5
#define BAD_HELLO -6
#define WRONG_MESSAGE -7
#define MISSING_REQUEST_CONTEXT -8
#define AUTHENTICATION_FAILURE -9
#define BAD_RECORD -10
#define BAD_TICKET -11

// alerts
#define ILLEGAL_PARAMETER 0x2F
#define UNEXPECTED_MESSAGE 0x0A
#define DECRYPT_ERROR 0x33
#define BAD_CERTIFICATE 0x2A
#define UNSUPPORTED_EXTENSION 0x6E

using namespace core;

//function return structure
typedef struct 
{
    unsign32 val;
    int err;
} ret;

// crypto context. Length of K=0 for no crypto.
typedef struct
{
    char k[TLS_MAX_KEY];
    char iv[12];
    octet K;
    octet IV;
    unsign32 record;
} crypto;

// ticket context
typedef struct 
{
    char tick[TLS_MAX_TICKET_SIZE];
    char nonce[32];
    octet TICK;
    octet NONCE;
    int lifetime;
    unsign32 age_obfuscator;
    unsign32 max_early_data;
    unsign32 birth;
} ticket;

// crypto capabilities structure
typedef struct 
{
    int nsg;
    int supportedGroups[TLS_MAX_SUPPORTED_GROUPS];
    int nsc;
    int ciphers[TLS_MAX_CIPHER_SUITES];
    int nsa;
    int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
} capabilities;

// unified hashing
typedef struct 
{
    hash256 sh32;
    hash512 sh64;
    int hlen;
} unihash;

#endif



