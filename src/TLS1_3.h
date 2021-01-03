#ifndef TLS1_3_H
#define TLS1_3_H

// Some maximum sizes
// Handshake will fail if these sizes are exceeded
#define TLS_MAX_HASH 64
#define TLS_MAX_KEY 32
#define TLS_MAX_SIGNED_CERT_SIZE 5000
#define TLS_MAX_CERT_SIZE 4096
#define TLS_MAX_CERTCHAIN_SIZE 3*TLS_MAX_SIGNED_CERT_SIZE
#define TLS_X509_MAX_FIELD 80
#define TLS_MAX_SIGNED_CERT_B64 (1+(TLS_MAX_SIGNED_CERT_SIZE*4)/3)
#define TLS_MAX_SIGNATURE_SIZE 512
#define TLS_MAX_PUB_KEY_SIZE 512
#define TLS_MAX_SECRET_KEY_SIZE 512
#define TLS_MAX_ECC_FIELD 66
#define TLS_IV_SIZE 12
#define TLS_TAG_SIZE 16

#define TLS_MAX_SERVER_NAME 128
#define TLS_MAX_SUPPORTED_GROUPS 5
#define TLS_MAX_SUPPORTED_SIGS 12
#define TLS_MAX_KEY_SHARES 4
#define TLS_MAX_PSK_MODES 2
#define TLS_MAX_CIPHER_SUITES 5

#define TLS_MAX_CLIENT_RECORD 2048
#define TLS_MAX_TICKET_SIZE 256

#define TLS_MAX_EXTENSIONS 1024
#define TLS_MAX_SERVER_HELLO 1024
#define TLS_MAX_SERVER_RESPONSE 8192

// Cipher Suites
#define TLS_AES_128_GCM_SHA256 0x1301  // this is only one which MUST be implemented
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

// Supported groups
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

// record types
#define HSHAKE 0x16
#define APPLICATION 0x17
#define ALERT 0x15
#define CHANGE_CIPHER 0x14

// message types
#define CLIENT_HELLO 0x01
#define SERVER_HELLO 0x02
#define CERTIFICATE 0x0b
#define CERT_VERIFY 0x0f
#define FINISHED 0x14
#define ENCRYPTED_EXTENSIONS 0x08
#define TICKET 0x04

// server Hello reponses
#define SH_ALERT 1
#define NOT_TLS1_3 2
#define HS_RETRY 3
#define ID_MISMATCH 4
#define UNRECOGNIZED_EXT 5
#define BAD_HELLO 6

// alerts
#define ILLEGAL_PARAMETER 0x2F

#endif



