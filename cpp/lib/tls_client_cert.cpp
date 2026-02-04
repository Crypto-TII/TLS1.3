//
// Client Certificate data stored here
// My private key and my certificate
//
#include <stdlib.h>
#include "tls_certs.h"
#include "tls_x509.h"
#include "tls_sal.h"

#if CLIENT_CERT != NO_CERT

#if CLIENT_CERT == FROM_ROM

#if CLIENT_CERT_KIND == ECC_SS

// My personal ECDSA private key - Certificate expires Jan 2027
const char *myprivate=(char *)
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3DkvaA4S0pWnwu6t\n"
"I6bczti3Qkh3T0qwzpdL2nmzdNmhRANCAAQ42drg0b22Z7G/J9cbGgVUpS+g01qh\n"
"zrfdbaWVI6wnJ8eHRkk4vWjj46IqBBTMMDTu3J0X30STHnCsSl4nhELV\n"
"-----END PRIVATE KEY-----\n";

// self-signed cert
const char *mycert=(char *)
"-----BEGIN CERTIFICATE-----\n"
"MIICdDCCAhugAwIBAgIUW9i3XshoTf1kbkaYGXgdu62/je8wCgYIKoZIzj0EAwIw\n"
"gY8xCzAJBgNVBAYTAkFFMRIwEAYDVQQIDAlBYnUgRGhhYmkxEzARBgNVBAcMCllh\n"
"cyBpc2xhbmQxDDAKBgNVBAoMA1RJSTEMMAoGA1UECwwDQ1JDMRYwFAYDVQQDDA1N\n"
"aWNoYWVsIFNjb3R0MSMwIQYJKoZIhvcNAQkBFhRtaWNoYWVsLnNjb3R0QHRpaS5h\n"
"ZTAeFw0yNjAyMDMxMjQ2NDFaFw0yNzAyMDMxMjQ2NDFaMIGPMQswCQYDVQQGEwJB\n"
"RTESMBAGA1UECAwJQWJ1IERoYWJpMRMwEQYDVQQHDApZYXMgaXNsYW5kMQwwCgYD\n"
"VQQKDANUSUkxDDAKBgNVBAsMA0NSQzEWMBQGA1UEAwwNTWljaGFlbCBTY290dDEj\n"
"MCEGCSqGSIb3DQEJARYUbWljaGFlbC5zY290dEB0aWkuYWUwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAAQ42drg0b22Z7G/J9cbGgVUpS+g01qhzrfdbaWVI6wnJ8eH\n"
"Rkk4vWjj46IqBBTMMDTu3J0X30STHnCsSl4nhELVo1MwUTAdBgNVHQ4EFgQUHwGZ\n"
"X/Oz4wmMST6ZVYRa3N3cKyIwHwYDVR0jBBgwFoAUHwGZX/Oz4wmMST6ZVYRa3N3c\n"
"KyIwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiB2QNlCag9lWmSN\n"
"W1aw2gORSfiPjBTLTR7fOw75AvCDpAIgPUaTdkFFmmHAVnuUox1CfIfJ/acrosUE\n"
"5HfclrEdr8k=\n"
"-----END CERTIFICATE-----\n";

#endif

#if CLIENT_CERT_KIND == EDD_SS

// My personal EDDSA private key - Certificate expires Jan 2027
const char *myprivate=(char *)
"-----BEGIN PRIVATE KEY-----\n"
"MC4CAQAwBQYDK2VwBCIEIGR5W3P8ufR3YVJbot87TblmIbqAy7k0ZuV2Z35jEufc\n"
"-----END PRIVATE KEY-----\n";

// self-signed cert
const char *mycert=(char *)
"-----BEGIN CERTIFICATE-----\n"
"MIICNTCCAeegAwIBAgIUPbKhfEf6uzy1beG5vVyaTIJlgycwBQYDK2VwMIGPMQsw\n"
"CQYDVQQGEwJBRTESMBAGA1UECAwJQWJ1IERoYWJpMRMwEQYDVQQHDApZYXMgSXNs\n"
"YW5kMQwwCgYDVQQKDANUSUkxDDAKBgNVBAsMA0NSQzEWMBQGA1UEAwwNTWljaGFl\n"
"bCBTY290dDEjMCEGCSqGSIb3DQEJARYUbWljaGFlbC5zY290dEB0aWkuYWUwHhcN\n"
"MjYwMjAzMTI1NzMwWhcNMjcwMjAzMTI1NzMwWjCBjzELMAkGA1UEBhMCQUUxEjAQ\n"
"BgNVBAgMCUFidSBEaGFiaTETMBEGA1UEBwwKWWFzIElzbGFuZDEMMAoGA1UECgwD\n"
"VElJMQwwCgYDVQQLDANDUkMxFjAUBgNVBAMMDU1pY2hhZWwgU2NvdHQxIzAhBgkq\n"
"hkiG9w0BCQEWFG1pY2hhZWwuc2NvdHRAdGlpLmFlMCowBQYDK2VwAyEAORsCxG5K\n"
"AUcm8mgP9AEQQ0VABw5pOY7ghDMHIUE2f6ijUzBRMB0GA1UdDgQWBBT0eegB1wf5\n"
"FXjbOpbUoIb125pC0DAfBgNVHSMEGDAWgBT0eegB1wf5FXjbOpbUoIb125pC0DAP\n"
"BgNVHRMBAf8EBTADAQH/MAUGAytlcANBALOu5PzwMDRG6QG7v6sRTZJzZssr571C\n"
"EyV6VH0SG6d4YNwqxVTp1OtRv+9t5ivbowUFtGSFSnU85j2/Z6lG5w4=\n"
"-----END CERTIFICATE-----\n";

#endif


#if CLIENT_CERT_KIND == HW_1
// My first Arduino Nano RP2040 self-signed Cert. Private key is on the board slot 0. Expires November 2026
const char *myprivate=NULL;
const int hwsigalg=ECDSA_SECP256R1_SHA256;
const char *mycert=(char *) 
"-----BEGIN CERTIFICATE-----\n"
"MIIBKzCB0aADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMTEjAxMjM0NjI0QjIwMjYwRDdF\n"
"RTAeFw0yMTExMTgxMTAwMDBaFw0yNjExMTgxMTAwMDBaMB0xGzAZBgNVBAMTEjAxMjM0NjI0QjIw\n"
"MjYwRDdFRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDOFj/SnArwqM15cZs/bXppfTuAxgMzB\n"
"N3LS48xHSqpLhHlVnvOvWqyhE8v+ZX4Jzlo7Z9LGOG537EeldBeGjYijAjAAMAoGCCqGSM49BAMC\n"
"A0kAMEYCIQC9O1l85YX1+9vZ0t/SHQ3zFH5e7Vc8XtrZ+mTtMc5riwIhAL/SektrG3C0JwII0VV5\n"
"pSR9RRnuwo810km81P4S56/m\n"
"-----END CERTIFICATE-----\n";

#endif

#if CLIENT_CERT_KIND == HW_2
// My second Arduino Nano RP2040 self-signed Cert. Private key is on the board slot 0. Expires December 2026
const char *myprivate=NULL;
const int hwsigalg=ECDSA_SECP256R1_SHA256;
const char *mycert=(char *) 
"-----BEGIN CERTIFICATE-----\n"
"MIIBKzCB0aADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMTEjAxMjM2RDlBNkNDRUQ5RUNF\n"
"RTAeFw0yMTEyMjgxMjAwMDBaFw0yNjEyMjgxMjAwMDBaMB0xGzAZBgNVBAMTEjAxMjM2RDlBNkND\n"
"RUQ5RUNFRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBxL51SsKUIJ6Akw2IMsn3PMa5tm8kRT\n"
"NDLBHfvIPZh05hoVnR3LO4+Ho91dMbN38tVM71opoTzPtIWrj5L6WI6jAjAAMAoGCCqGSM49BAMC\n"
"A0kAMEYCIQDgqosqLRntTyehtDCuWcY6WP41sfwx1k78W6EkLpoDyQIhAPzxQawMjI9mLeePF6Kk\n"
"BzPRSurX7+nLFDC6u3pfmEY8\n"
"-----END CERTIFICATE-----\n";
#endif
/*
// My Arduino Nano 33 IoT self-signed Cert. Private key is on the board slot 0. Expires July 2031
const char *myprivate=NULL;

const char *mycert=(char *) 
"-----BEGIN CERTIFICATE-----\n"
"MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMB0xGzAZBgNVBAMTEjAxMjNBMDUz\n"
"MEQ0RkU1RUVFRTAeFw0yMTA3MDQxNTAwMDBaFw0zMTA3MDQxNTAwMDBaMB0xGzAZ\n"
"BgNVBAMTEjAxMjNBMDUzMEQ0RkU1RUVFRTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"
"A0IABL8xBsAdr4E1MZMoQeA6hmklaiidF8gpgZWmRkSfIIyHwMup/wsz4eTGAB5J\n"
"IhLI/gFGVjsAU+WK7ulsW5YgxCqjAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDYWgeH\n"
"TF7AcJH+3nr7VQo8acgoyhlPnR62xwjj0AsUcwIgQ9qgNjVtZgoZC5+fTpPyG7dt\n"
"1YI/aNe4SDOv0a2jtmc=\n"
"-----END CERTIFICATE-----\n";
*/

#if CLIENT_CERT_KIND == RSA_SS
// My personal private key RSA 2048 bits - expires Jan 2027
const char *myprivate=(char *)
"-----BEGIN PRIVATE KEY-----\n"
"MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCt+UXsP4V2azwo\n"
"V6eqcn4yOBbiEL2BLRGrt29sWl72ws+vyxe5W9kArbRsyziiOhFrkGwmP/utOjAw\n"
"8nGLIPcQXuQOwdDgp0uzjT31OYeVdnbaad/hASrCoyEnF2QO6bkuq43szP2wn/Bv\n"
"IW09uZyfjJxoR6uE+5XYEfF1tJg7d5XPVOL7WxG94KqgJdO41FIyPGZVnhlg58+r\n"
"eZf2KuNLeIFODUpNT8ZJyQuBl37q2i+vZQU4KYo/zDH5WiSiI5LWNl1wZaZvYYQF\n"
"gCykZUJxKMly7bNtYEpIeQbbvIZMe9hb/0jrmfaNewQJqRjXGdBvvEiBH8oN0LBQ\n"
"1n7uRveBAgMBAAECgf8cU8DSzmBs1WxhRJYlEzZE3OzSeeyLHpnj8MiuhapuKqhS\n"
"5RouqSaKW57y3oItyK8yBhsteAlWXQugT+6FyylKzNo7TjROs6rhJmTd9Bo3Ck8R\n"
"O/z8Bq9lRbegNYUC/YOfHZkLazs8UEaz8Pl9KvKr41tArzFQp4b/1AECJsZZrrhK\n"
"F1CGGMOozepu91DZsscMh/S4DtIfCPSjfCgdwQWOMDZr2z/jDTJJ5PSzMYdiY+qW\n"
"EW0lV1lXCUI66eaK3RPWyPWAx1xA5T0paTmCXeQCU4CmY7Yyjd3l7PAYd/GLI/PG\n"
"fmokDoZSl54IumrdsvPnLDbtwxRRUCsIQdBQ3isCgYEA3lh8DuB8evhUjtmQGJse\n"
"sOVC1fN0XmW4lBX/dTLpnOjsK8PS3Gk+xfm3kD/49Chl3PR6MdsWzp7JtZIvxTKx\n"
"2hWp6bV1pzaRORYIJni+InF/UCRXXpOWUCMweE99a35MCHvppES6za/tvGok7f7u\n"
"mWBmC2Etg0TxtC+5E1V3mqcCgYEAyE51fMqylMKOZ4XCcvvoK3gzYHkj2JasSQ6K\n"
"fvPuxWS0fOlfm4XYFnnf2b6qXBheLAUmSI4w+H6/A0JSvkV2sBzzl1/MjQe9adr+\n"
"1PbTe3Ezhfy3VHEhIUr4GFnfO5HSpneia4x577No7Mr0Q+Wt3RFy+IGqKHcfTrxN\n"
"bhgaKZcCgYEAjRZ00jPciWNetK6VYye7V+CCgqTTaLr/Xuh+i23dE3Yxtqux967I\n"
"6HNG6b/OR5AC4yw3Bb/SPxY/RHoY2fcLKCmrAePlXk+f4yt5zH+9lrmSYdZNonPg\n"
"Y8WQkidOnJEtygxm+5epOa+zGWX5PRQRbz3eQsZNTQjInt/RftUy6e0CgYAl6uRG\n"
"qUBA9MtsQV/b0F/Uyr4/Bu+IMo2OjtgczCRo7XVVKABXOnD7YDrFx1gMcvhwsNDc\n"
"bz5J7ARQo59yMUgUcoaSIypfkBWFElWnDspd1cIBHSO/MmMpID3yriCZ8DLGHGN8\n"
"pGz4uSelm429xJ6y+HihHjqNym78wpyNuLZLJQKBgANiMLdEyT8KytDufyEMVoQL\n"
"UWEO8YNCX2KeufPy83In4EiRRvC6P180M8gczHtz9CtXhVmrTsoJQ/FEyM7GfxKd\n"
"3ZYpGylxPvzMTcdkEccy5BoRu0Wx3KYo4T0HizH9KhsJOmmMecI0JkH5I3rUPboO\n"
"BeP/5t6Bl0JrZKkz7X7m\n"
"-----END PRIVATE KEY-----\n";

// A chain of certificates - just one self-signed here
const char *mycert=(char *)
"-----BEGIN CERTIFICATE-----\n"
"MIIEATCCAumgAwIBAgIUcrcZ9UeGlFO4YJo7hv6dApm0FP4wDQYJKoZIhvcNAQEL\n"
"BQAwgY8xCzAJBgNVBAYTAkFFMRIwEAYDVQQIDAlBYnUgRGhhYmkxEzARBgNVBAcM\n"
"CllhcyBJc2xhbmQxDDAKBgNVBAoMA1RJSTEMMAoGA1UECwwDQ1JDMRYwFAYDVQQD\n"
"DA1NaWNoYWVsIFNjb3R0MSMwIQYJKoZIhvcNAQkBFhRtaWNoYWVsLnNjb3R0QHRp\n"
"aS5hZTAeFw0yNjAyMDMxMzE3MTBaFw0yNzAyMDMxMzE3MTBaMIGPMQswCQYDVQQG\n"
"EwJBRTESMBAGA1UECAwJQWJ1IERoYWJpMRMwEQYDVQQHDApZYXMgSXNsYW5kMQww\n"
"CgYDVQQKDANUSUkxDDAKBgNVBAsMA0NSQzEWMBQGA1UEAwwNTWljaGFlbCBTY290\n"
"dDEjMCEGCSqGSIb3DQEJARYUbWljaGFlbC5zY290dEB0aWkuYWUwggEiMA0GCSqG\n"
"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt+UXsP4V2azwoV6eqcn4yOBbiEL2BLRGr\n"
"t29sWl72ws+vyxe5W9kArbRsyziiOhFrkGwmP/utOjAw8nGLIPcQXuQOwdDgp0uz\n"
"jT31OYeVdnbaad/hASrCoyEnF2QO6bkuq43szP2wn/BvIW09uZyfjJxoR6uE+5XY\n"
"EfF1tJg7d5XPVOL7WxG94KqgJdO41FIyPGZVnhlg58+reZf2KuNLeIFODUpNT8ZJ\n"
"yQuBl37q2i+vZQU4KYo/zDH5WiSiI5LWNl1wZaZvYYQFgCykZUJxKMly7bNtYEpI\n"
"eQbbvIZMe9hb/0jrmfaNewQJqRjXGdBvvEiBH8oN0LBQ1n7uRveBAgMBAAGjUzBR\n"
"MB0GA1UdDgQWBBRPM5JdGM3+cIiR4c+6SMemsnHsgDAfBgNVHSMEGDAWgBRPM5Jd\n"
"GM3+cIiR4c+6SMemsnHsgDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\n"
"A4IBAQAjiKfMRK5psBp1Vj7jFiVnEJu4cwlcH2TBbM/H7deaB0deWi/d2+8JnXGB\n"
"M1LH9Zt7W7QtvqtfutreI+gmzwjKu1vw9xcEmVU8MHJov/bd6hZtc/ucoF2Zi0iD\n"
"Z2202vG8g3TMPgVDdiEwtZr30HkDhy9rH4cF47KNWE35PPXJPECdR+efnqF2Ivxr\n"
"Sig+DWff2E6JkU+YqHeyY6cony2vCBHxYjbWGFtUMDoVoYCUFM9cZmp3gMpDKKdy\n"
"jbqja0mdm6HjyVnwWMD+iVH1/t5W134YDeHPI477Xffme/UBzWHxTytGVVEd/5lk\n"
"UZT6dB4zf8+DlF3Lr9S3FmYtboVb\n"
"-----END CERTIFICATE-----\n";


#endif

#if CLIENT_CERT_KIND == HYB_SS

// TBD

#endif

#if CLIENT_CERT_KIND == DLT_SS

//TBD

#endif

#if CLIENT_CERT_KIND == HW_1 || CLIENT_CERT_KIND == HW_2
#define HSM_SECRET
#endif


#endif

static int get_sigalg(pktype *pk) {
    if (pk->type==X509_ECC) {
        if (pk->curve==USE_NIST256) {
            return ECDSA_SECP256R1_SHA256; // as long as this is a client capability
        }
        if (pk->curve==USE_NIST384) {
            return ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
        }
    }
    if (pk->type==X509_RSA) {
       return RSA_PSS_RSAE_SHA256;
    }
    if (pk->type==X509_DLM) {
        return MLDSA65;
    }
    if (pk->type==X509_HY1) {
        return MLDSA44_ED25519;
    }
    if (pk->type==X509_ECD) {
        if (pk->curve==USE_ED25519) {
            return ED25519;
        }
        if (pk->curve==USE_ED448) {
            return ED448;
        }
    }            
    return 0;    
}

static int add_cert_sig_type(pktype *pk,int reqlen,unsign16 *requirements) 
{
    int len=reqlen;
    if (pk->type==X509_ECC) {
        if (pk->curve==USE_NIST256) {
            requirements[len]=ECDSA_SECP256R1_SHA256; // as long as this is a client capability
            len+=1;
        }
        if (pk->curve==USE_NIST384) {
            requirements[len]=ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
            len+=1;
        }
        return len;
    }
    if (pk->type==X509_RSA) {
       if (pk->hash==X509_H256) {
           requirements[len]=RSA_PKCS1_SHA256;
           len+=1;
       }
       if (pk->hash==X509_H384) {
           requirements[len]=RSA_PKCS1_SHA384;
           len+=1;
       }
       if (pk->hash==X509_H512) {
           requirements[len]=RSA_PKCS1_SHA512;
           len+=1;
       }       
       return len;
    }

    if (pk->type==X509_DLM) {
        requirements[len]=MLDSA65;
        len+=1;
        return len;
    }
    if (pk->type==X509_HY1) {
        requirements[len]=MLDSA44_ED25519;
        len+=1;
        requirements[len]=MLDSA44;
        len+=1;
        requirements[len]=ED25519;
        len+=1;
        return len;  // *** also need to check that secp256r1 is supported - kind indicates that both signature keys are in privkey
    }
    if (pk->type==X509_ECD) {
        if (pk->curve==USE_ED25519) {
            requirements[len]=ED25519;
            len+=1;
            return len;
        }
        if (pk->curve==USE_ED448) {
            requirements[len]=ED448;
            len+=1;
            return len;
        }
    }
    return len;  
}

static void initCredential(credential *C) 
{
    C->CERTCHAIN.len=0;
    C->CERTCHAIN.max=TLS_MAX_CLIENT_CHAIN_SIZE;
    C->CERTCHAIN.val=C->certchain;
    
    C->PUBLICKEY.len=0;
    C->PUBLICKEY.max=TLS_MAX_SIG_PUB_KEY_SIZE;
    C->PUBLICKEY.val=C->publickey;    
    
    C->SECRETKEY.len=0;
    C->SECRETKEY.max=TLS_MAX_SIG_SECRET_KEY_SIZE;
    C->SECRETKEY.val=C->secretkey;  
    
    C->nreqs=0;
    C->nreqsraw=0;  
    C->sigalg=0;   
}


// read a line of base64


#if CLIENT_CERT == FROM_FILE
static int readaline(char *line,FILE *fp)
{
    int i=0;
    if (!fgets(line,80,fp)) return 0;
    while (line[i]!=0) i++;
    i--;
    while (line[i]=='\r' || line[i]=='\n') i--;
    i++;
    line[i]=0;
    return i;
}

#else
static int readaline(char *line,const char *rom,int &ptr)
{
    int i=0;
    if (rom[ptr]==0) return 0;
    while (rom[ptr]!='\n')
    {
        line[i++]=rom[ptr++];
    }
    ptr++; // jump over CR
    line[i]=0;
    return i;
}
#endif

// process certchain and private key from OpenSSL format
bool setCredential(credential *C)
{
    int i,ptr,pkptr,len;
    int kind;
    pktype pk;
#ifdef SHALLOW_STACK
    char *b=(char *)malloc(TLS_MAX_CERT_B64);
    octad SC={0,TLS_MAX_CERT_B64,b};       // optimization - share memory - can convert from base64 to binary in place
#else
    char b[TLS_MAX_CERT_B64];    // maximum size key/cert
    octad SC={0,sizeof(b),b};    // share memory - can convert from base64 to binary in place
#endif
    char sig[TLS_MAX_SIGNATURE_SIZE];
    octad SIG={0,sizeof(sig),sig};
    int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
    char line[80]; 
    
    initCredential(C);
    bool offered=false; // if not in hardware or software
    
#if HSM_SECRET
    C->sigalg=hwsigalg;
    offered=true;
#else   
// unless signing with private key takes place in protected hardware, SAL should have it in software
#if CLIENT_CERT==FROM_FILE 
    FILE *fp=fopen(CLIENT_KEY_PATH,"r");
    if (fp==NULL) {
#ifdef SHALLOW_STACK
        free(b);
#endif
        return false;
    }
    readaline(line,fp);
#else    
    ptr=0; 
    readaline(line,myprivate,ptr);
#endif
    for (i=0;;)
    {
#if CLIENT_CERT==FROM_FILE 
        readaline(line,fp);
#else    
        readaline(line,myprivate,ptr);
#endif        
        if (line[0]=='-') break; 
        for (int j=0;line[j]!=0;j++)
            b[i++]=line[j];
    }
    b[i]=0;  
//puts(b);        
    OCT_from_base64(&SC,b);
    pk=X509_extract_private_key(&SC, &(C->SECRETKEY)); // returns signature type
    kind=get_sigalg(&pk); // Client must implement algorithm to do signature - make sure its in the SAL!
    C->sigalg=kind;
    
    //printf("len= %d kind=%x\n",C->SECRETKEY.len,kind);
    
    int nsa=SAL_sigs(sigAlgs);
 
    for (int i=0;i<nsa;i++) {
        if (kind==sigAlgs[i]) offered=true;
    } 
#endif
  
// get first cert    
// chain length is 1 (self-signed) or 2 (server+intermediate - root is not transmitted)

#if CLIENT_CERT==FROM_FILE
    fclose(fp); 
    fp=fopen(CLIENT_CERT_PATH,"r");
    if (fp==NULL) {
#ifdef SHALLOW_STACK
        free(b);
#endif
        return false;
    }
    readaline(line,fp);
#else    
    ptr=0; 
    readaline(line,mycert,ptr);
#endif
    for (i=0;;)
    {
#if CLIENT_CERT==FROM_FILE 
        readaline(line,fp);
#else    
        readaline(line,mycert,ptr);
#endif
        if (line[0]=='-') break;
        for (int j=0;line[j]!=0;j++)
            b[i++]=line[j];
    }
    b[i]=0;
  //puts(b);  
    OCT_from_base64(&SC,b);
// add to certchain   
    OCT_append_int(&(C->CERTCHAIN),SC.len,3);
    OCT_append_octad(&(C->CERTCHAIN),&SC);
    OCT_append_int(&(C->CERTCHAIN),0,2);  // add no certificate extensions
         
    pk=X509_extract_cert_sig(&SC,&SIG);
    C->nreqs=add_cert_sig_type(&pk,C->nreqs,C->requirements);   
    C->nreqsraw=C->nreqs;   
  
 // extract its public key (for possible RAW public key use)   
    X509_extract_cert(&SC,&SC);
    len=X509_find_public_key(&SC,&pkptr);
    octad PK={len,len,&SC.val[pkptr]};
    OCT_append_int(&(C->PUBLICKEY),len,3);
    OCT_append_octad(&(C->PUBLICKEY),&PK);
#if CLIENT_CERT==FROM_FILE    
    if (readaline(line,fp)) {
#else
    if (readaline(line,mycert,ptr)) { // there is an intermediate cert
#endif   
        for (i=0;;)
        {
#if CLIENT_CERT==FROM_FILE 
            readaline(line,fp);
#else    
            readaline(line,mycert,ptr);
#endif
            if (line[0]=='-') break;
            for (int j=0;line[j]!=0;j++)
                b[i++]=line[j];
        } 
        b[i]=0;
    //puts(b);    
        OCT_from_base64(&SC,b);       	
       
// add to certchain   
    	OCT_append_int(&(C->CERTCHAIN),SC.len,3);
    	OCT_append_octad(&(C->CERTCHAIN),&SC);
    	OCT_append_int(&(C->CERTCHAIN),0,2);  // add no certificate extensions
    	pk=X509_extract_cert_sig(&SC,&SIG);
    	C->nreqs=add_cert_sig_type(&pk,C->nreqs,C->requirements); 
    }
#if CLIENT_CERT==FROM_FILE  
    fclose(fp);
#endif    
#ifdef SHALLOW_STACK
    free(b);
#endif   
    if (!offered) return false;    
    return true;  
}

#endif





