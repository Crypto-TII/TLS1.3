// Server Cert Verify Code
//
#include "tls_scv.h"

// check that SCVSIG is digital signature (using sigalg algorithm) of some TLS1.3 specific message+transcript hash, as verified by Server Certificate public key CERTPK
// Only supports MUST supported algorithms.
// RFC8446:     "A TLS-compliant application MUST support digital signatures with
//              rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
//              CertificateVerify and certificates), and ecdsa_secp256r1_sha256."

bool IS_SERVER_CERT_VERIFY(int sigalg,octet *SCVSIG,octet *H,octet *CERTPK)
{
// Server Certificate Verify
    int sha;
    char scv[100+TLS_MAX_HASH];
    octet SCV={0,sizeof(scv),scv};
    char p[TLS_MAX_SIGNATURE_SIZE];
    octet P={0,sizeof(p),p};
    char r[TLS_MAX_ECC_FIELD];
    octet R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octet S={0,sizeof(s),s};

// TLS1.3 message that was signed
    OCT_jbyte(&SCV,32,64);  // 64 spaces
    OCT_jstring(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_jbyte(&SCV,0,1);  // add 0 character
    OCT_joctet(&SCV,H);   // add Transcript Hash - could be MAX_HASH

    int len=SCVSIG->len;
    int rlen,slen,Int,der,ptr=0;

    switch (sigalg)
    {
    case RSA_PSS_RSAE_SHA256:
        sha=32; // SHA256

        if (len=0x100)
        { // 2048 bit RSA
            RSA2048::rsa_public_key PK;
            PK.e = 65537;
            RSA2048::RSA_fromOctet(PK.n, CERTPK);
            RSA2048::RSA_ENCRYPT(&PK, SCVSIG, &P);
            if (core::PSS_VERIFY(sha,&SCV,&P)) 
                return true;
        }
        if (len=0x200)
        { // 4096 bit RSA
            RSA4096::rsa_public_key PK;
            PK.e = 65537;
            RSA4096::RSA_fromOctet(PK.n, CERTPK);
            RSA4096::RSA_ENCRYPT(&PK, SCVSIG, &P);
            if (core::PSS_VERIFY(sha,&SCV,&P)) 
                return true;
        }
        return false;
    case ECDSA_SECP256R1_SHA256:  // DER encoded !!
        sha=0x20; // SHA256
        ptr=0;
        der=parseByte(SCVSIG,ptr);
        if (der!=0x30) return false;
        slen=parseByte(SCVSIG,ptr);
        if (slen+2!=len) return false;

        Int=parseByte(SCVSIG,ptr);
        if (Int!=0x02) return false;
        rlen=parseByte(SCVSIG,ptr);
        if (rlen==0x21)
        {
            rlen--;
            int lzero=parseByte(SCVSIG,ptr);
            if (lzero!=0) return false;
        }
        parseOctet(&R,0x20,SCVSIG,ptr);

        Int=parseByte(SCVSIG,ptr);
        if (Int!=0x02) return false;
        slen=parseByte(SCVSIG,ptr);
        if (slen==0x21)
        {
            slen--;
            int lzero=parseByte(SCVSIG,ptr);
            if (lzero!=0) return false;
        }
        parseOctet(&S,0x20,SCVSIG,ptr);

if (rlen<0x20 || slen<0x20) printf("**** Signature problem\n");
//printf("R= ");OCT_output(&R);
//printf("S= ");OCT_output(&S);

        if (NIST256::ECP_VP_DSA(sha, CERTPK, &SCV, &R, &S) == 0)
            return true;
    case ECDSA_SECP384R1_SHA384:
        sha=0x30;
        ptr=0;
        der=parseByte(SCVSIG,ptr);
        if (der!=0x30) return false;
        slen=parseByte(SCVSIG,ptr);
        if (slen+2!=len) return false;

        Int=parseByte(SCVSIG,ptr);
        if (Int!=0x02) return false;
        rlen=parseByte(SCVSIG,ptr);
        if (rlen==0x31)
        { // there must be a leading zero
            rlen--;
            int lzero=parseByte(SCVSIG,ptr);
            if (lzero!=0) return false;
        }
        parseOctet(&R,0x30,SCVSIG,ptr);

        Int=parseByte(SCVSIG,ptr);
        if (Int!=0x02) return false;
        slen=parseByte(SCVSIG,ptr);
        if (slen==0x31)
        { // there must be a leading zero
            slen--;
            int lzero=parseByte(SCVSIG,ptr);
            if (lzero!=0) return false;
        }
        parseOctet(&S,0x30,SCVSIG,ptr);

if (rlen<0x30 || slen<0x30) printf("**** Signature problem\n");
//printf("R= ");OCT_output(&R);
//printf("S= ");OCT_output(&S);

        if (NIST384::ECP_VP_DSA(sha, CERTPK, &SCV, &R, &S) == 0)
        return true;


    default :
        printf("WHOOPS - Unsupported signature type\n");
        return false;
    }
    return false;
}
