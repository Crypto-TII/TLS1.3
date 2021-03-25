// TLS1.3 Server Certificate Chain Code
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_logger.h"
#include "tls_cacerts.h"

// combine Common Name, Organisation Name and Unit Name to make unique determination
static void FULL_NAME(octet *FN,octet *CERT,int ic)
{
    int c,len;
    OCT_clear(FN);
    c=X509_find_entity_property(CERT,&X509_MN,ic,&len);
    OCT_jbytes(FN,&CERT->val[c],len);
    OCT_jbyte(FN,'/',1); // spacer
    c=X509_find_entity_property(CERT,&X509_ON,ic,&len);
    OCT_jbytes(FN,&CERT->val[c],len);
    OCT_jbyte(FN,'/',1);
    c=X509_find_entity_property(CERT,&X509_UN,ic,&len);
    OCT_jbytes(FN,&CERT->val[c],len);
}

static bool readaline(char *line,const char *rom,int &ptr)
{
    int i=0;
    if (rom[ptr]==0) return false;
    while (rom[ptr]!='\n')
    {
        line[i++]=rom[ptr++];
    }
    ptr++; // jump over CR
    return true;
}

// Extract public key from a certificate
static pktype GET_PUBLIC_KEY_FROM_CERT(octet *CERT,octet *PUBLIC_KEY)
{
    pktype pk=X509_extract_public_key(CERT, PUBLIC_KEY);  // pull out its public key
    return pk;
}

static bool CHECK_HOSTNAME_IN_CERT(octet *CERT,char *hostname)
{
    int len;
    int ic=X509_find_extensions(CERT);
    int c=X509_find_extension(CERT,&X509_AN,ic,&len);
    return (bool)X509_find_alt_name(CERT,c,hostname);
}

static bool CHECK_VALIDITY(octet *CERT)
{
    int len;
    int ic = X509_find_validity(CERT);
    int c = X509_find_expiry_date(CERT, ic);
    int year=2000+(CERT->val[c]-'0')*10 +CERT->val[c+1]-'0';
    if (year<THIS_YEAR) return false;
    return true;
}

// given root issuer and public key type of signature, search through root CAs and return root public key
// This is a simple linear search through CA certificates found in the ca-certificates.crt file (borrowed from Ubuntu)
// This file should be in Read-Only-Memory

static bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY)
{
    char ca[TLS_X509_MAX_FIELD];
    octet CA={0,sizeof(ca),ca};
    char owner[TLS_X509_MAX_FIELD];
    octet OWNER={0,sizeof(owner),owner};
    char sc[TLS_MAX_ROOT_CERT_SIZE];  // server certificate
    octet SC={0,sizeof(sc),sc};
    char b[TLS_MAX_ROOT_CERT_B64];  // maximum size for CA root signed certs in base64
    char line[80]; int ptr=0;

    for (;;)
    {
        int i=0;
        if (!readaline(line,cacerts,ptr)) break;
        for (;;)
        {
            readaline(line,cacerts,ptr);
            if (line[0]=='-') break;
            for (int j=0;j<64;j++)
                b[i++]=line[j];
            b[i]=0;
        }
        OCT_frombase64(&SC,b);
        int c = X509_extract_cert(&SC, &SC);  // extract Cert from Signed Cert

        int ic = X509_find_issuer(&SC);
        FULL_NAME(&OWNER,&SC,ic);

        if (!CHECK_VALIDITY(&SC))
        { // Its expired!
            return false;
        }

        if (OCT_comp(&OWNER,ISSUER))
        {
            pktype pt = X509_extract_public_key(&SC, PUBKEY);
            if (st.type==pt.type && st.curve==pt.curve) 
            { // found CA cert 
                return true;
            }
        } 
    }
    return false;  // couldn't find it
}

// strip signature off certificate. Return signature type
static pktype STRIP_DOWN_CERT(octet *CERT,octet *SIG,octet *ISSUER,octet *SUBJECT)
{
    int c,ic,len;

    pktype sg=X509_extract_cert_sig(CERT,SIG);
    X509_extract_cert(CERT,CERT);

    ic = X509_find_issuer(CERT);
    FULL_NAME(ISSUER,CERT,ic);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Full Issuer Name Length= ",(char *)"%d",ISSUER->len,NULL);
#endif

    ic = X509_find_subject(CERT);
    FULL_NAME(SUBJECT,CERT,ic);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Full Subject Name Length= ",(char *)"%d",SUBJECT->len,NULL);
#endif

    return sg;
}

// Check signature on Certificate given signature type and public key
static bool CHECK_CERT_SIG(pktype st,octet *CERT,octet *SIG, octet *PUBKEY)
{
    int sha=0;
    if (st.hash == X509_H256) sha = SHA256;
    if (st.hash == X509_H384) sha = SHA384;
    if (st.hash == X509_H512) sha = SHA512;
    if (st.hash == 0)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Hash Function not supported\n",NULL,0,NULL);
#endif
        return false;
    }
    if (st.type == 0)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Unable to check cert signature\n",NULL,0,NULL);
#endif
        return false;
    }
    if (st.type == X509_ECC)
    { // its an ECC signature
        char r[TLS_MAX_ECC_FIELD];
        octet R={0,sizeof(r),r};
        char s[TLS_MAX_ECC_FIELD];
        octet S={0,sizeof(s),s};
        int res,siglen=SIG->len/2;
        for (int i=0;i<siglen;i++)
        {
            OCT_jbyte(&R,SIG->val[i],1);
            OCT_jbyte(&S,SIG->val[i+siglen],1);
        }
#if VERBOSITY >= IO_DEBUG
        logger((char *)"SIG= \n",NULL,0,&R);
        logger((char *)"",NULL,0,&S);
        logger((char *)"\nECC PUBLIC KEY= \n",NULL,0,PUBKEY);
        logger((char *)"Checking ECC Signature on Cert ",(char *)"%d",st.curve,NULL);
#endif
        if (st.curve==USE_NIST256)
            res = NIST256::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (st.curve==USE_NIST384)
            res = NIST384::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
#if VERBOSITY >= IO_DEBUG
        if (res != 0)
            logger((char *)"ECP Public Key is invalid!\n",NULL,0,NULL);
        else logger((char *)"ECP Public Key is Valid\n",NULL,0,NULL);
#endif
        if (st.curve==USE_NIST256)
            res=NIST256::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);
        if (st.curve==USE_NIST384)
            res=NIST384::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);

        if (res!=0)
        {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"***ECDSA Verification Failed\n",NULL,0,NULL);
#endif
            return false;
        } else {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"ECDSA Signature/Verification succeeded \n",NULL,0,NULL);
#endif
            return true;
        }
    }
    if (st.type == X509_RSA)
    { // its an RSA signature
        int res;
#if VERBOSITY >= IO_DEBUG
        logger((char *)"st.curve= ",(char *)"%d",st.curve,NULL);
        logger((char *)"SIG= ",NULL,0,SIG);
        logger((char *)"\nRSA PUBLIC KEY= ",NULL,0,PUBKEY);
        logger((char *)"Checking RSA Signature on Cert \n",NULL,0,NULL);
#endif
        if (st.curve==2048)
        {
            char p1[RFS_RSA2048];
            octet P1={0,sizeof(p1),p1};
            char p2[RFS_RSA2048];
            octet P2={0,sizeof(p2),p2};
            RSA2048::rsa_public_key PK;
            PK.e = 65537; // assuming this!
            RSA2048::RSA_fromOctet(PK.n, PUBKEY);
            core::PKCS15(sha, CERT, &P1);
            RSA2048::RSA_ENCRYPT(&PK, SIG, &P2);
            res=OCT_comp(&P1, &P2);
        }
        if (st.curve==4096)
        {
            char p1[RFS_RSA4096];
            octet P1={0,sizeof(p1),p1};
            char p2[RFS_RSA4096];
            octet P2={0,sizeof(p2),p2};
            RSA4096::rsa_public_key PK;
            PK.e = 65537; // assuming this!
            RSA4096::RSA_fromOctet(PK.n, PUBKEY);
            core::PKCS15(sha, CERT, &P1);
            RSA4096::RSA_ENCRYPT(&PK, SIG, &P2);
            res=OCT_comp(&P1, &P2);
        } 
        if (res)
        {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"RSA Signature/Verification succeeded \n",NULL,0,NULL);
#endif
            return true;
        } else {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"***RSA Verification Failed\n",NULL,0,NULL);
#endif
            return false;
        }
    }
    return false;
}

// extract server public key, and check validity of certificate chain
// This will need improving!
// Assumes simple chain Server Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
bool CHECK_CERT_CHAIN(octet *CERTCHAIN,char *hostname,octet *PUBKEY)
{
    ret r;
    int len,c,ptr=0;
    pktype sst,ist,spt,ipt;
    char ssig[TLS_MAX_SIGNATURE_SIZE];  // signature on server certificate
    octet SSIG={0,sizeof(ssig),ssig};
    char isig[TLS_MAX_SIGNATURE_SIZE];  // signature on intermediate certificate
    octet ISIG={0,sizeof(isig),isig};

// Clever re-use of memory - use pointers into cert chain rather than extracting certs
    octet SCERT;  // server certificate
    SCERT.len=0;
    octet ICERT;  // signature on intermediate certificate
    ICERT.len=0;

    char ipk[TLS_MAX_PUB_KEY_SIZE];  // Public Key from Intermediate Cert
    octet IPK = {0, sizeof(ipk), ipk};

    char rpk[TLS_MAX_PUB_KEY_SIZE];  // Public Key Root Certificate
    octet RPK = {0, sizeof(rpk), rpk};

    char issuer[TLS_X509_MAX_FIELD];  
    octet ISSUER={0,sizeof(issuer),issuer};
    char subject[TLS_X509_MAX_FIELD];
    octet SUBJECT={0,sizeof(subject),subject};

// Extract and process Server Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false;// get length of first (server) certificate
    r=parseOctetptr(&SCERT,len,CERTCHAIN,ptr); if (r.err) return false;

#if VERBOSITY >= IO_DEBUG
    logCert(&SCERT);
#endif
//printf("Signed cert len= %d\n",SCERT.len);

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions

    sst=STRIP_DOWN_CERT(&SCERT,&SSIG,&ISSUER,&SUBJECT);    // extract signature
    spt=GET_PUBLIC_KEY_FROM_CERT(&SCERT,PUBKEY);           // extract  public key

    if (!CHECK_HOSTNAME_IN_CERT(&SCERT,hostname))
    { // Check that certificate covers the server URL
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Hostname not found in certificate\n",NULL,0,NULL);
#endif
        return false;
    }
    if (!CHECK_VALIDITY(&SCERT))
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Certificate has expired\n",NULL,0,NULL);
#endif
        return false;
    }

    if (sst.type==0)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Unrecognised Signature Type\n",NULL,0,NULL);
#endif
        return false;
    }
#if VERBOSITY >= IO_DEBUG
    logCertDetails((char *)"Parsing Server certificate\n",PUBKEY,spt,&SSIG,sst,&ISSUER,&SUBJECT);
#endif
    if (OCT_comp(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return true;   // not fatal for development purposes
    }

// Extract and process Intermediate Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false; // get length of next certificate
    r=parseOctetptr(&ICERT,len,CERTCHAIN,ptr); if (r.err) return false;

#if VERBOSITY >= IO_DEBUG
    logCert(&ICERT);
#endif

//printf("Signed cert len= %d\n",ICERT.len);

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions

#if VERBOSITY >= IO_PROTOCOL
    if (ptr<CERTCHAIN->len)
        logger((char *)"Warning - there are unprocessed Certificates in the Chain\n",NULL,0,NULL);
#endif

//printf("CERTCHAIN->len= %d ptr= %d\n",CERTCHAIN->len,ptr);

    ist=STRIP_DOWN_CERT(&ICERT,&ISIG,&ISSUER,&SUBJECT);
    ipt=GET_PUBLIC_KEY_FROM_CERT(&ICERT,&IPK);

    if (!CHECK_VALIDITY(&ICERT))
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate has expired\n",NULL,0,NULL);
#endif
        return false;
    }

#if VERBOSITY >= IO_DEBUG
    logCertDetails((char *)"Parsing Intermediate certificate\n",&IPK,ipt,&ISIG,ist,&ISSUER,&SUBJECT);
#endif
    if (CHECK_CERT_SIG(sst,&SCERT,&SSIG,&IPK)) {  // Check server cert signature with inter cert public key
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate Chain sig is OK\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate Chain sig is NOT OK\n",NULL,0,NULL);
#endif
        return false;
    }

    if (OCT_comp(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return true;   // not fatal for development purposes
    }
/*
printf("Cert Chain ptr=%d length= %d\n",ptr,CERTCHAIN->len);
r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false; // get length of next certificate
r=parseOctetptr(&SCERT,len,CERTCHAIN,ptr); if (r.err) return false;
logCert(&SCERT);
*/

// Find Root of Trust
// Find root certificate public key
    if (FIND_ROOT_CA(&ISSUER,ist,&RPK)) {
#if VERBOSITY >= IO_DEBUG        
        logger((char *)"\nPublic Key from root cert= ",NULL,0,&RPK);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate not found\n",NULL,0,NULL);
#endif
        return false;
    }

    if (CHECK_CERT_SIG(ist,&ICERT,&ISIG,&RPK)) {  // Check inter cert signature with root cert public key
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate sig is OK!!!!\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate sig is NOT OK\n",NULL,0,NULL);
#endif
        return false;
    }
    return true;
}

// check that SCVSIG is digital signature (using sigalg algorithm) of some TLS1.3 specific message+transcript hash, as verified by Server Certificate public key CERTPK
// Only supports MUST supported algorithms.
// RFC8446:     "A TLS-compliant application MUST support digital signatures with
//              rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
//              CertificateVerify and certificates), and ecdsa_secp256r1_sha256."

bool IS_SERVER_CERT_VERIFY(int sigalg,octet *SCVSIG,octet *H,octet *CERTPK)
{
// Server Certificate Verify
    ret rt;
    int lzero,sha;
    char scv[100+TLS_MAX_HASH];
    octet SCV={0,sizeof(scv),scv};
    char p[TLS_MAX_SIGNATURE_SIZE];
    octet P={0,sizeof(p),p};
    char r[TLS_MAX_ECC_FIELD];
    octet R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octet S={0,sizeof(s),s};

// TLS1.3 message that was signed
    OCT_jbyte(&SCV,32,64); // 64 spaces
    OCT_jstring(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_jbyte(&SCV,0,1);   // add 0 character
    OCT_joctet(&SCV,H);    // add Transcript Hash 

    int len=SCVSIG->len;
    int rlen,slen,Int,der,ptr=0;

// probably need to support more cases
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
        rt=parseByte(SCVSIG,ptr); der=rt.val;
        if (rt.err || der!=0x30) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen+2!=len) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); rlen=rt.val;
        if (rt.err) return false;
        if (rlen==0x21)
        { // one too big
            rlen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&R,0x20,SCVSIG,ptr); if (rt.err) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen==0x21)
        { // one too big
            slen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&S,0x20,SCVSIG,ptr); if (rt.err) return false;

        if (rlen<0x20 || slen<0x20) return false;

        if (NIST256::ECP_VP_DSA(sha, CERTPK, &SCV, &R, &S) == 0)
            return true;
    case ECDSA_SECP384R1_SHA384:
        sha=0x30;
        ptr=0;
        rt=parseByte(SCVSIG,ptr); der=rt.val;
        if (rt.err || der!=0x30) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen+2!=len) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); rlen=rt.val;
        if (rt.err || rlen==0x31)
        { // there must be a leading zero...
            rlen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&R,0x30,SCVSIG,ptr);  if (rt.err) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err) return false;
        if (slen==0x31)
        { // there must be a leading zero..
            slen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&S,0x30,SCVSIG,ptr); if (rt.err) return false;

        if (rlen<0x30 || slen<0x30) return false;

        if (NIST384::ECP_VP_DSA(sha, CERTPK, &SCV, &R, &S) == 0)
        return true;

    default :
#if VERBOSITY >= IO_DEBUG
        logger((char *)"WHOOPS - Unsupported signature type\n",NULL,0,NULL);
#endif
        return false;
    }
    return false;
}

