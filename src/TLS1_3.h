#ifndef TLS1_3_H
#define TLS1_3_H

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

#define TLS1_3 0x0304

// Extensions
#define SERVER_NAME 0x0000
#define SUPPORTED_GROUPS 0x000a
#define SIG_ALGS 0x000d
#define KEY_SHARE 0x0033
#define PSK_MODE 0x002d
#define TLS_VER 0x002b


#endif



