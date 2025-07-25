#![allow(dead_code)]
//! Main TII TLS 1.3 Configuration File for constants and structures
// see bottom of file for user definables

pub const HRR:&str="CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";  
pub const DISCONNECTED: usize = 0;
pub const CONNECTED: usize = 1;
pub const HANDSHAKING: usize = 2;

// Cipher Suites 
/// AES128/SHA256/GCM cipher suite
pub const AES_128_GCM_SHA256: u16 = 0x1301;       
/// AES256/SHA384/GCM cipher suite 
pub const AES_256_GCM_SHA384: u16 =  0x1302;      
/// CHACHA20/SHA256/POLY1305 cipher suite 
pub const CHACHA20_POLY1305_SHA256: u16 = 0x1303; 
//pub const AES_128_CCM_SHA256: u16 = 0x1304;       // AES/SHA256/CCM cipher suite - optional 
//pub const AES_128_CCM_8_SHA256: u16 = 0x1305;     // AES/SHA256/CCM 8 cipher suite - optional 

// Signature algorithms for TLS1.3 and Certs that we can handle 
/// Supported ECDSA Signature algorithm 
pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;   
/// Supported ECDSA Signature algorithm
pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503; 
/// Supported RSA Signature algorithm
pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804; 
/// Supported RSA Signature algorithm
pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
/// Supported RSA Signature algorithm
pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806; 
/// Supported RSA Signature algorithm
pub const RSA_PKCS1_SHA256: u16 = 0x0401; 
/// Supported RSA Signature algorithm
pub const RSA_PKCS1_SHA384: u16 = 0x0501;
/// Supported RSA Signature algorithm
pub const RSA_PKCS1_SHA512: u16 = 0x0601;  
/// Dilithium3 Signature algorithm
pub const MLDSA65: u16 = 0x0905;  
/// Dilithium2 Signature algorithm
pub const MLDSA44: u16 = 0x0904; 
/// Non-standard - used in hybrid schemes 
pub const ECDSA_SECP256R1_SHA384: u16 = 0x0413; 
/// Dilithium2 Hybrid Signature algorithm 
pub const MLDSA44_P256: u16 = 0xFF06; //0x0907; // this type can be negotiated, but always implemented seperately by SAL
// Ed25519 EdDSA Signature algorithm
pub const ED25519: u16 = 0x0807;                   
// Ed448 EdDSA Signature algorithm
pub const ED448: u16 = 0x0808; 

// Maximum sizes for stack arrays
/// Max ECC field size in bytes
pub const MAX_ECC_FIELD:usize = 66;                  
/// Maximum memory required to store hash function state
pub const MAX_HASH_STATE:usize = 768;     
/// Maximum hash output length in bytes 
pub const MAX_HASH: usize = 64;         
/// Maximum key length in bytes
pub const MAX_KEY: usize = 32;           
/// Maximum X.509 field size 
pub const MAX_X509_FIELD:usize = 256;               

// IO buffer limits
/// Maximum Input buffer size.
pub const MAX_IBUFF_SIZE: usize = 16384+256;         
/// Max Plaintext Fragment size 
pub const MAX_PLAIN_FRAG: usize = 16384;        
/// Max Ciphertext Fragment size 
pub const MAX_CIPHER_FRAG: usize = 16384+256;       

// Supported CRYPTO_SETTINGs
/// ECC only support only
pub const TINY_ECC: usize = 0;  
/// ECC + RSA support
pub const TYPICAL: usize = 1;  
/// POST_QUANTUM support
pub const POST_QUANTUM: usize = 3;    
/// HYBRID support
pub const HYBRID: usize = 4;
/// EDDSA support
pub const EDDSA: usize = 2;

// supported SERVER CERTIFICATE settings
/// Client certificate from ROM
pub const FROM_ROM: usize = 1;
///Client certificate from file
pub const FROM_FILE:usize = 2;


// These sizes assume CRYPTO_SETTING is for POST_QUANTUM and are set for Post Quantum-sized certs and keys
// Can be greatly reduced for non-PQ - would be much smaller for ECC/RSA
pub const MAX_CERT_SIZE:usize = 6144;               // Max cert size 
pub const MAX_HELLO: usize = 2048;                  // Maximum Hello size (less extensions) KEX public key is largest component

// These all blow up for post quantum
pub const MAX_SIG_PUBLIC_KEY: usize = 1952+100;         // Maximum signature Public key size Dilithium 3
pub const MAX_SIG_SECRET_KEY: usize = 4000+100;         // Maximum signature Public key size Dilithium 3
pub const MAX_SIGNATURE_SIZE: usize = 3309+100;         // Maximum signature size in bytes - Dilithium 3  
pub const MAX_KEX_PUBLIC_KEY: usize = 1184+32;          // Maximum key exchange public key size (also Encapsulation size for KEM) - was 136 pre-quantum
pub const MAX_KEX_CIPHERTEXT: usize = 1088+32;          // Maximum key exchange (KEM) ciphertext size
pub const MAX_KEX_SECRET_KEY: usize = 2400+32;          // Maximum key exchange Secret key size

pub const MAX_SHARED_SECRET_SIZE:usize = 256;           // Maximum shared secret size - was 66 pre-quantum 

// Certificate size limits
pub const MAX_SERVER_CHAIN_LEN:usize = 2;               // Maximum Server Chain length (omit Root Cert)
pub const MAX_SERVER_CHAIN_SIZE:usize = MAX_SERVER_CHAIN_LEN*MAX_CERT_SIZE;
//pub const MAX_CLIENT_CHAIN_LEN:usize = 1;             // Maximum Client Chain length
//pub const MAX_CLIENT_CHAIN_SIZE:usize = MAX_CLIENT_CHAIN_LEN*MAX_CERT_SIZE;

// Bloated by testing clients offering pre TLS1.3 suites and groups
pub const MAX_CIPHER_SUITES: usize = 384;           // *********************
pub const MAX_SUPPORTED_GROUPS: usize = 64;         // *********************
pub const MAX_SUPPORTED_SIGS: usize = 64;           // *********************

pub const MAX_SERVER_NAME: usize = 128;          // Max server name size in bytes 
//pub const MAX_COOKIE: usize = 128;             // Max Cookie size  
pub const MAX_IV_SIZE: usize = 12;               // Max IV size in bytes 
pub const MAX_TAG_SIZE:usize = 16;               // Max HMAC tag length in bytes 

//pub const MAX_FRAG:usize = 4;
//pub const MAX_RECORD:usize = 4096;               // default Maximum Record size

pub const MAX_OUTPUT_RECORD_SIZE:usize = 4096;   // Max output record size (fragment size)
pub const MAX_OBUFF_SIZE:usize = MAX_OUTPUT_RECORD_SIZE+MAX_TAG_SIZE+6; // Max output buffer size

// Both of these are bumped up by PQ IBE and Hybrid
pub const MAX_TICKET_SIZE:usize = 4196; //4000+161 PQ+IBE
pub const MAX_EXTENSIONS:usize = 6144;       

// message types 
pub const CLIENT_HELLO: u8 = 0x01;               // Client Hello message  
pub const SERVER_HELLO: u8 = 0x02;               // Server Hello message  
pub const CERTIFICATE: u8 = 0x0b;                // Certificate message 
pub const CERT_REQUEST: u8 = 0x0d;               // Certificate Request 
pub const CERT_VERIFY: u8 = 0x0f;                // Certificate Verify message 
pub const FINISHED: u8 = 0x14;                   // Handshake Finished message 
pub const ENCRYPTED_EXTENSIONS: u8 = 0x08;       // Encrypted Extensions message 
pub const TICKET: u8 = 0x04;                     // Ticket message
pub const KEY_UPDATE: u8 = 0x18;                 // Key Update message 
pub const MESSAGE_HASH: u8 = 0xFE;               // Special synthetic message hash message     
pub const END_OF_EARLY_DATA: u8 = 0x05;          // End of Early Data message   
// pseudo message types
pub const HANDSHAKE_RETRY: usize = 0x102;        // Handshake retry 
pub const TRY_RESUMPTION: usize = 0x103;         // Try for resumption

pub const UPDATE_NOT_REQUESTED: usize=0;    
pub const UPDATE_REQUESTED: usize=1;

// Key exchange groups
pub const X25519: u16 = 0x001d;
pub const SECP256R1: u16 = 0x0017;
pub const SECP384R1: u16 = 0x0018;
pub const MLKEM768: u16 = 0x0201;
pub const SIDH: u16 = 0x4243;
pub const HYBRID_KX: u16 = 0x11ec;
//pub const SECP521R1: u16 = 0x0019;
//pub const X448: u16 = 0x001e;

// TLS versions
//pub const TLS1_0:usize = 0x0301;                 // TLS 1.0 version 
pub const TLS1_2:usize = 0x0303;                   // TLS 1.2 version 
pub const TLS1_3:usize = 0x0304;                   // TLS 1.3 version 

// Extensions 
pub const SERVER_NAME:usize = 0x0000;             // Server Name extension 
pub const SUPPORTED_GROUPS:usize = 0x000a;        // Supported Group extension 
pub const SIG_ALGS:usize = 0x000d;                // Signature algorithms extension 
pub const POST_HANDSHAKE_AUTH:usize = 0x0031;     // Post Handshake Authentication
pub const SIG_ALGS_CERT:usize = 0x0032;           // Signature algorithms Certificate extension 
pub const KEY_SHARE:usize = 0x0033;               // Key Share extension 
pub const PSK_MODE:usize = 0x002d;                // Preshared key mode extension 
pub const PRESHARED_KEY:usize = 0x0029;           // Preshared key extension 
pub const TLS_VER:usize = 0x002b;                 // TLS version extension 
//pub const COOKIE:usize = 0x002c;                // Cookie extension 
pub const EARLY_DATA:usize = 0x002a;              // Early Data extension 
pub const MAX_FRAG_LENGTH:usize = 0x0001;         // max fragmentation length extension 
pub const PADDING:usize = 0x0015;                 // Padding extension 
pub const APP_PROTOCOL:usize = 0x0010;            // Application Layer Protocol Negotiation (ALPN) 
pub const RECORD_SIZE_LIMIT:usize = 0x001c;       // Record Size Limit 
pub const CLIENT_CERT_TYPE:usize = 0x0013;        // Client Certificate type
pub const SERVER_CERT_TYPE:usize = 0x0014;        // Server Certificate type
pub const HEARTBEAT:usize = 0x000f;               // Heartbeat
pub const CERT_AUTHORITIES:usize = 0x002f;        // Certificate Authorities

// pre-shared Key (PSK) modes 
//pub const PSKOK:usize = 0x00;                   // Preshared Key only mode 
pub const PSKWECDHE:usize = 0x01;                 // Preshared Key with Diffie-Hellman key exchange mode 

// Causes of server error - which should generate a client alert 
pub const NOT_TLS1_3:isize= -2;                   // Wrong version error, not TLS1.3 
pub const BAD_CERT_CHAIN:isize= -3;               // Bad Certificate Chain error 
pub const ID_MISMATCH:isize= -4;                  // Session ID mismatch error 
pub const UNRECOGNIZED_EXT:isize= -5;             // Unrecognised extension error 
pub const BAD_HELLO:isize= -6;                    // badly formed Hello message error 
pub const WRONG_MESSAGE:isize= -7;                // Message out-of-order error 
pub const MISSING_REQUEST_CONTEXT:isize= -8;      // Request context missing error 
pub const AUTHENTICATION_FAILURE:isize= -9;       // Authentication error - AEAD Tag incorrect 
pub const BAD_RECORD:isize= -10;                  // Badly formed Record received 
pub const BAD_TICKET:isize= -11;                  // Badly formed Ticket received 
pub const NOT_EXPECTED:isize= -12;                // Received ack for something not requested 
pub const CA_NOT_FOUND:isize= -13;                // Certificate Authority not found 
pub const CERT_OUTOFDATE:isize= -14;              // Certificate Expired 
pub const MEM_OVERFLOW:isize= -15;                // Memory Overflow 
pub const FORBIDDEN_EXTENSION:isize= -16;         // Forbidden Encrypted Extension 
pub const MAX_EXCEEDED:isize= -17;                // Maximum record size exceeded 
pub const EMPTY_CERT_CHAIN:isize= -18;            // Empty Certificate Message 
pub const SELF_SIGNED_CERT:isize= -20;            // Self-signed certificate detected
pub const TIME_OUT:isize= -21;                    // time out
pub const ERROR_ALERT_RECEIVED:isize=-22;         // alert received
pub const BAD_MESSAGE:isize=-23;                  // Badly formed message
pub const CERT_VERIFY_FAIL:isize= -24;            // Certificate Verification failure */
pub const BAD_PROTOCOL:isize=-25;                 // Bad Protocol
pub const BAD_HANDSHAKE:isize=-26;                // Could not agree
pub const BAD_REQUEST_UPDATE:isize= -27;          // Bad Request Update value
pub const CLOSURE_ALERT_RECEIVED:isize=-28;       // alert received
pub const FINISH_FAIL:isize= -29;                 // Certificate Verification failure */
pub const MISSING_EXTENSIONS:isize= -30;          // Missing one or more extesions
pub const BAD_PARAMETER:isize= -31;               // Bad crypto parameter

// record types 
pub const HSHAKE:u8= 0x16;                        // Handshake record 
pub const APPLICATION:u8=  0x17;                  // Application record 
pub const ALERT:u8=  0x15;                        // Alert record 
pub const CHANGE_CIPHER:u8=  0x14;                // Change Cipher record 
pub const HEART_BEAT:u8= 0x18;                    // Heart Beat
// pseudo record types
pub const TIMED_OUT:u8=  0x01;                    // Time-out  

// Standard Hash Types
pub const SHA256_T: usize = 1;           // SHA256 hash  
pub const SHA384_T: usize = 2;           // SHA384 hash  
pub const SHA512_T: usize = 3;           // SHA512 hash  

// client alerts 
pub const ILLEGAL_PARAMETER: u8 = 0x2F;           // Illegal parameter alert 
pub const UNEXPECTED_MESSAGE: u8 =  0x0A;         // Unexpected message alert 
pub const DECRYPT_ERROR: u8 =  0x33;              // Decryption error alert 
pub const BAD_CERTIFICATE: u8 =  0x2A;            // Bad certificate alert 
pub const UNSUPPORTED_EXTENSION: u8 =  0x6E;      // Unsupported extension alert 
pub const UNKNOWN_CA: u8 =  0x30;                 // Unrecognised Certificate Authority 
pub const CERTIFICATE_EXPIRED: u8 =  0x2D;        // Certificate Expired 
pub const CERTIFICATE_REQUIRED: u8 = 0x74;        // Certificate Expected
pub const PROTOCOL_VERSION: u8 =  0x46;           // Wrong TLS version 
pub const DECODE_ERROR: u8 =  0x32;               // Decode error alert 
pub const RECORD_OVERFLOW: u8 =  0x16;            // Record Overflow 
pub const BAD_RECORD_MAC: u8 = 0x14;              // Bad Record Mac 
pub const CLOSE_NOTIFY: u8 =  0x00;               // Orderly shut down of connection 
pub const NO_APPLICATION_PROTOCOL: u8 = 0x78;     // Wrong Application protocol
pub const HANDSHAKE_FAILURE: u8 = 0x28;           // Handshake failed
pub const MISSING_EXTENSION: u8 = 0x6D;           // Missing extensions

/// Universal Hash Function structure 
pub struct UNIHASH {
    pub state: [u8;MAX_HASH_STATE],
    pub htype: usize
}

// logging
pub const IO_NONE:usize= 0;           // Run silently 
//pub const IO_ERROR:usize= 1;        // Report only errors
pub const IO_APPLICATION:usize= 2;    // Report application traffic + errors 
pub const IO_PROTOCOL:usize= 3;       // Report protocol progress + application traffic 
pub const IO_DEBUG:usize= 4;          // print lots of debug information + protocol progress + application progress 

/// map causes to alerts
pub fn alert_from_cause(rtn: isize) -> u8
{
    match rtn {
        NOT_TLS1_3 => return ILLEGAL_PARAMETER,
        ID_MISMATCH => return ILLEGAL_PARAMETER,
        UNRECOGNIZED_EXT => return ILLEGAL_PARAMETER,
        BAD_HELLO => return DECODE_ERROR,        
        WRONG_MESSAGE => return UNEXPECTED_MESSAGE,
        BAD_CERT_CHAIN => return BAD_CERTIFICATE,
        MISSING_REQUEST_CONTEXT => return ILLEGAL_PARAMETER,
        AUTHENTICATION_FAILURE => return BAD_RECORD_MAC,
        BAD_RECORD => return DECODE_ERROR,
        BAD_TICKET => return ILLEGAL_PARAMETER,
        NOT_EXPECTED => return UNSUPPORTED_EXTENSION,
        CA_NOT_FOUND => return UNKNOWN_CA,
        CERT_OUTOFDATE => return CERTIFICATE_EXPIRED,
        MEM_OVERFLOW => return DECODE_ERROR,
        FORBIDDEN_EXTENSION => return ILLEGAL_PARAMETER,
        MAX_EXCEEDED => return RECORD_OVERFLOW,
        EMPTY_CERT_CHAIN => return CERTIFICATE_REQUIRED,
        TIME_OUT => return CLOSE_NOTIFY,
        ERROR_ALERT_RECEIVED => return CLOSE_NOTIFY,
        CLOSURE_ALERT_RECEIVED => return CLOSE_NOTIFY,
        BAD_MESSAGE => return DECODE_ERROR,
        BAD_PARAMETER => return ILLEGAL_PARAMETER,
        BAD_PROTOCOL => return NO_APPLICATION_PROTOCOL,
        BAD_HANDSHAKE => return HANDSHAKE_FAILURE,
        CERT_VERIFY_FAIL => return DECRYPT_ERROR,
        FINISH_FAIL => return DECRYPT_ERROR,
        BAD_REQUEST_UPDATE => return ILLEGAL_PARAMETER,
        MISSING_EXTENSIONS => return MISSING_EXTENSION,
        _ => return ILLEGAL_PARAMETER   
    }
}

// ticket origin
pub const FULL_HANDSHAKE:usize =  1;    // Came from Full Handshake 
pub const EXTERNAL_PSK:usize =  2;      // External Pre-Shared Key 

// protocol returns..
pub const TLS_FAILURE:usize = 0;
pub const TLS_SUCCESS:usize = 1;

//pub const SET_RECORD_LIMIT: bool=false;   // Max record size (non-standard?) extension
pub const LOG_OUTPUT_TRUNCATION: usize= 512; // Hex digits output before truncation 

pub const X509_CERT:u8 = 0;
pub const RAW_PUBLIC_KEY:u8 = 2;

// ******************************* User defined controls ******************************************
pub const VERBOSITY:usize= IO_PROTOCOL;     // Set log reporting level
pub const ALLOW_SELF_SIGNED:bool= true;     // allow self-signed certs
pub const CRYPTO_SETTING: usize = TYPICAL;  // Decide on crypto setting - determines certificate chain
//pub const THIS_YEAR: usize = 2025;          // Set to this year - was crudely used to deprecate old certificates - no longer used       
pub const APPLICATION_PROTOCOL:&str="http/1.1";  // ALPN extension
pub const SERVER_CERT:usize= FROM_ROM;     // client-side authentication
pub const CERTIFICATE_REQUEST: bool=false;  // Does server require client authentication?
pub const TICKET_LIFETIME: u32 = 86400;     // 86400 seconds in a day
pub const MAX_EARLY_DATA: usize = 1024;     // maximum amount of early data a client can send 
pub const PAD_SHORT_RECORDS:bool=false;     // pad short output records - slower but safer
pub const ALLOW_RAW_SERVER_PUBLIC_KEY:bool=true; // Allow raw public key from the server
pub const ALLOW_RAW_CLIENT_PUBLIC_KEY:bool=true; // Allow client raw public key
// may need to set these all to false for fuzzing 
pub const ALLOW_IBE_PSKS: bool= true;       // allow IBE PSK connections
pub const MERGE_MESSAGES: bool= true;       // allow merging of messages into single record
pub const RESPECT_MAX_FRAQ_REQUEST: bool= true; // respect client request for maximum record (fragment) sizes
pub const ENABLE_HEARTBEATS: bool= false;   // Enable heart-beats
pub const PEER_CAN_HEARTBEAT: bool=true;    // allow peer to heartbeat
