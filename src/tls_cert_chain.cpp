// TLS1.3 Server Certificate Chain Code

#include "tls_cert_chain.h"

// combine Common Name, Organisation Name and Unit Name to make unique determination
static void FULL_NAME(octad *FN,octad *CERT,int ic)
{
    int c,len;
    OCT_kill(FN);
    c=X509_find_entity_property(CERT,&X509_MN,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len);
    OCT_append_byte(FN,'/',1); // spacer
    c=X509_find_entity_property(CERT,&X509_ON,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len);
    OCT_append_byte(FN,'/',1);
    c=X509_find_entity_property(CERT,&X509_UN,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len);
}

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

// Extract public key from a certificate
static pktype GET_PUBLIC_KEY_FROM_CERT(octad *CERT,octad *PUBLIC_KEY)
{
    pktype pk=X509_extract_public_key(CERT, PUBLIC_KEY);  // pull out its public key
    return pk;
}

static bool CHECK_HOSTNAME_IN_CERT(octad *CERT,char *hostname)
{
    int len;
    int ic=X509_find_extensions(CERT);
    int c=X509_find_extension(CERT,&X509_AN,ic,&len);
    return (bool)X509_find_alt_name(CERT,c,hostname);
}

static bool CHECK_VALIDITY(octad *CERT)
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

static bool FIND_ROOT_CA(octad* ISSUER,pktype st,octad *PUBKEY)
{
    char ca[TLS_X509_MAX_FIELD];
    octad CA={0,sizeof(ca),ca};
    char owner[TLS_X509_MAX_FIELD];
    octad OWNER={0,sizeof(owner),owner};
    char sc[TLS_MAX_ROOT_CERT_SIZE];  // server certificate
    octad SC={0,sizeof(sc),sc};
    char b[TLS_MAX_ROOT_CERT_B64];  // maximum size for CA root signed certs in base64
    char line[80]; int ptr=0;

    for (;;)
    {
        int len,i=0;
        if (!readaline(line,cacerts,ptr)) break;
        for (;;)
        {
            len=readaline(line,cacerts,ptr);
            if (line[0]=='-') break;
            for (int j=0;j<len;j++)
                b[i++]=line[j];
            b[i]=0;
        }
        OCT_from_base64(&SC,b);
        int c = X509_extract_cert(&SC, &SC);  // extract Cert from Signed Cert

        int ic = X509_find_issuer(&SC);
        FULL_NAME(&OWNER,&SC,ic);

        if (!CHECK_VALIDITY(&SC))
        { // Its expired!
            continue;
        }

        if (OCT_compare(&OWNER,ISSUER))
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
static pktype STRIP_DOWN_CERT(octad *CERT,octad *SIG,octad *ISSUER,octad *SUBJECT)
{
    int c,ic,len;

    pktype sg=X509_extract_cert_sig(CERT,SIG);
    X509_extract_cert(CERT,CERT);

    ic = X509_find_issuer(CERT);
    FULL_NAME(ISSUER,CERT,ic);

//#if VERBOSITY >= IO_DEBUG
//    logger((char *)"Full Issuer Name Length= ",(char *)"%d",ISSUER->len,NULL);
//#endif

    ic = X509_find_subject(CERT);
    FULL_NAME(SUBJECT,CERT,ic);

//#if VERBOSITY >= IO_DEBUG
//    logger((char *)"Full Subject Name Length= ",(char *)"%d",SUBJECT->len,NULL);
//#endif

    return sg;
}

// Check signature on Certificate given signature type and public key
static bool CHECK_CERT_SIG(pktype st,octad *CERT,octad *SIG, octad *PUBKEY)
{
    int sha=0;
    bool res=false;
    if (st.hash == X509_H256) sha = TLS_SHA256;
    if (st.hash == X509_H384) sha = TLS_SHA384;
    if (st.hash == X509_H512) sha = TLS_SHA512;
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
        octad R={0,sizeof(r),r};
        char s[TLS_MAX_ECC_FIELD];
        octad S={0,sizeof(s),s};
        int siglen=SIG->len/2;
        for (int i=0;i<siglen;i++)
        {
            OCT_append_byte(&R,SIG->val[i],1);
            OCT_append_byte(&S,SIG->val[i+siglen],1);
        }
#if VERBOSITY >= IO_DEBUG
        logger((char *)"SIG R= \n",NULL,0,&R);
        logger((char *)"SIG S= \n",NULL,0,&S);
        logger((char *)"\nECC PUBLIC KEY= \n",NULL,0,PUBKEY);
        logger((char *)"Checking ECC Signature on Cert ",(char *)"%d",st.curve,NULL);
#endif
        if (st.curve==USE_NIST256)
            res=SECP256R1_ECDSA_VERIFY(sha,CERT,&R,&S,PUBKEY);
        if (st.curve==USE_NIST384)
            res=SECP384R1_ECDSA_VERIFY(sha,CERT,&R,&S,PUBKEY);        

        if (res)
        {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"ECDSA Signature/Verification succeeded \n",NULL,0,NULL);
#endif
            return true;
        } else {
#if VERBOSITY >= IO_DEBUG
            logger((char *)"***ECDSA Verification Failed\n",NULL,0,NULL);
#endif
            return false;
        }
    }
    if (st.type == X509_RSA)
    { // its an RSA signature - assuming PKCS1.5 encoding
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Checking RSA Signature on Cert \n",NULL,0,NULL);
#endif
        if (st.curve==2048)
        {
            res=RSA_2048_PKCS15_VERIFY(sha,CERT,SIG,PUBKEY);
        }
        if (st.curve==4096)
        {
            res=RSA_4096_PKCS15_VERIFY(sha,CERT,SIG,PUBKEY);
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

// Read in client private key from .pem file
// Read in certificate, and make a certificate chain
int GET_CLIENT_KEY_AND_CERTCHAIN(int nccsalgs,int *csigAlgs,octad *PRIVKEY,octad *CERTCHAIN)
{
    int i,kind,ptr,len;
    char sc[TLS_MAX_MYCERT_SIZE];  // X.509 .pem file (is it a cert or a cert chain??)
    octad SC={0,sizeof(sc),sc};
    char b[TLS_MAX_MYCERT_B64];    // maximum size key/cert
    char line[80]; 
    
    OCT_kill(CERTCHAIN);
// should be a chain of certificates, one after the other. May just be one self-signed
    ptr=0;
    for (;;)
    {
        i=0;
        if (!readaline(line,mycert,ptr)) break;
        for (;;)
        {
            len=readaline(line,mycert,ptr);
            if (line[0]=='-') break;
            for (int j=0;j<len;j++)
                b[i++]=line[j];
            b[i]=0;
        }
        OCT_from_base64(&SC,b);

// add to Certificate Chain
        OCT_append_int(CERTCHAIN,SC.len,3);
        OCT_append_octad(CERTCHAIN,&SC);
        OCT_append_int(CERTCHAIN,0,2);  // add no certificate extensions
    }

    ptr=0; i=0;
    readaline(line,myprivate,ptr);
    for (;;)
    {
        len=readaline(line,myprivate,ptr);
        if (line[0]=='-') break;
        for (int j=0;j<len;j++)
            b[i++]=line[j];
        b[i]=0;
    }
    OCT_from_base64(&SC,b);

    pktype pk= X509_extract_private_key(&SC, PRIVKEY); // returns signature type

// figure out kind of signature client can apply - should be tested against client capabilities
// Not that no hash type is specified - its just a private key, no algorithm specified
    kind=0;
    if (pk.type==X509_ECC)
    {
        if (pk.curve==USE_NIST256) kind=ECDSA_SECP256R1_SHA256;  // as long as this is a client capability
        if (pk.curve==USE_NIST384) kind=ECDSA_SECP384R1_SHA384;  // as long as this is a client capability
    }
    if (pk.type==X509_RSA)
    {
        kind=RSA_PSS_RSAE_SHA256;  // as long as this is a capability
    }

    for (i=0;i<nccsalgs;i++)
    {
        if (kind==csigAlgs[i]) break;
    }

    return kind;
}

// extract server public key, and check validity of certificate chain
// This will need improving!
// Assumes simple chain Server Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
bool CHECK_CERT_CHAIN(octad *CERTCHAIN,char *hostname,octad *PUBKEY)
{
    ret r;
    int len,c,ptr=0;
    pktype sst,ist,spt,ipt;
    char ssig[TLS_MAX_SIGNATURE_SIZE];  // signature on server certificate
    octad SSIG={0,sizeof(ssig),ssig};
    char isig[TLS_MAX_SIGNATURE_SIZE];  // signature on intermediate certificate
    octad ISIG={0,sizeof(isig),isig};

// Clever re-use of memory - use pointers into cert chain rather than extracting certs
    octad SCERT;  // server certificate
    SCERT.len=0;
    octad ICERT;  // signature on intermediate certificate
    ICERT.len=0;

    char ipk[TLS_MAX_PUB_KEY_SIZE];  // Public Key from Intermediate Cert
    octad IPK = {0, sizeof(ipk), ipk};

    char rpk[TLS_MAX_PUB_KEY_SIZE];  // Public Key Root Certificate
    octad RPK = {0, sizeof(rpk), rpk};

    char issuer[TLS_X509_MAX_FIELD];  
    octad ISSUER={0,sizeof(issuer),issuer};
    char subject[TLS_X509_MAX_FIELD];
    octad SUBJECT={0,sizeof(subject),subject};

// Extract and process Server Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false;// get length of first (server) certificate
    r=parseoctadptr(&SCERT,len,CERTCHAIN,ptr); if (r.err) return false;

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions

    sst=STRIP_DOWN_CERT(&SCERT,&SSIG,&ISSUER,&SUBJECT);    // extract signature
    spt=GET_PUBLIC_KEY_FROM_CERT(&SCERT,PUBKEY);           // extract  public key

    if (!CHECK_HOSTNAME_IN_CERT(&SCERT,hostname))
    { // Check that certificate covers the server URL
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Hostname not found in certificate\n",NULL,0,NULL);
#endif
        if (strcmp(hostname,"localhost")!=0) return false;
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
    if (OCT_compare(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return true;   // not fatal for development purposes
    }

// Extract and process Intermediate Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false; // get length of next certificate
    r=parseoctadptr(&ICERT,len,CERTCHAIN,ptr); if (r.err) return false;

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions

#if VERBOSITY >= IO_PROTOCOL
    if (ptr<CERTCHAIN->len)
        logger((char *)"Warning - there are unprocessed Certificates in the Chain\n",NULL,0,NULL);
#endif

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

    if (OCT_compare(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return true;   // not fatal for development purposes
    }

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

// Create Client Cert Verify message, a digital signature using KEY on some TLS1.3 specific message+transcript hash
void CREATE_CLIENT_CERT_VERIFIER(int sigAlg,octad *H,octad *KEY,octad *CCVSIG)
{
    int sha,len;
    char ccv[100+TLS_MAX_HASH];
    octad CCV={0,sizeof(ccv),ccv};
// create TLS1.3 message to be signed
    OCT_append_byte(&CCV,32,64); // 64 spaces
    OCT_append_string(&CCV,(char *)"TLS 1.3, client CertificateVerify");  // 33 chars
    OCT_append_byte(&CCV,0,1);   // add 0 character
    OCT_append_octad(&CCV,H);    // add Transcript Hash 

    switch (sigAlg)
    {
    case RSA_PSS_RSAE_SHA256:
    {
        sha=TLS_SHA256; // SHA256
        len=KEY->len/5;   // length of p and q

        if (len==0x80)
        { // 2048 bit RSA
            RSA_2048_PSS_RSAE_SIGN(sha,KEY,&CCV,CCVSIG);
        }

        if (len==0x100)
        { // 4096 bit RSA
            RSA_4096_PSS_RSAE_SIGN(sha,KEY,&CCV,CCVSIG);
        }
    }
    break;
    case ECDSA_SECP256R1_SHA256:
    case ECDSA_SECP384R1_SHA384:
    { 
        bool cinc=false;
        bool dinc=false;
        int clen;      // curve field/group length
        char c[TLS_MAX_ECC_FIELD];
        octad C={0,sizeof(c),c};
        char d[TLS_MAX_ECC_FIELD];
        octad D={0,sizeof(c),c};

        if (sigAlg==ECDSA_SECP256R1_SHA256)
        {
            clen=32;
            sha=TLS_SHA256; 
            SECP256R1_ECDSA_SIGN(sha,KEY,&CCV,&C,&D);
        }
        if (sigAlg==ECDSA_SECP384R1_SHA384)
        {
            clen=48;
            sha=TLS_SHA384;
            SECP384R1_ECDSA_SIGN(sha,KEY,&CCV,&C,&D);
        }
        
        if (C.val[0]&0x80) cinc=true;
        if (D.val[0]&0x80) dinc=true;

        len=2*clen+4;
        if (cinc) len++;    // -ve values need leading zero inserted
        if (dinc) len++;
 
        OCT_kill(CCVSIG);
        OCT_append_byte(CCVSIG,0x30,1);  // ASN.1 SEQ
        OCT_append_byte(CCVSIG,len,1);
// C
        OCT_append_byte(CCVSIG,0x02,1);  // ASN.1 INT type
        if (cinc)
        {
            OCT_append_byte(CCVSIG,clen+1,1);
            OCT_append_byte(CCVSIG,0,1);
        } else {
            OCT_append_byte(CCVSIG,clen,1);
        }
        OCT_append_octad(CCVSIG,&C);
// D
        OCT_append_byte(CCVSIG,0x02,1);  // ASN.1 INT type
        if (dinc)
        {
            OCT_append_byte(CCVSIG,clen+1,1);
            OCT_append_byte(CCVSIG,0,1);
        } else {
            OCT_append_byte(CCVSIG,clen,1);
        }
        OCT_append_octad(CCVSIG,&D);
    }
    break;
    }
    return;
}

// check that SCVSIG is digital signature (using sigalg algorithm) of some TLS1.3 specific message+transcript hash, as verified by Server Certificate public key CERTPK
// Only supports MUST supported algorithms.
// RFC8446:     "A TLS-compliant application MUST support digital signatures with
//              rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
//              CertificateVerify and certificates), and ecdsa_secp256r1_sha256."

bool IS_SERVER_CERT_VERIFY(int sigalg,octad *SCVSIG,octad *H,octad *CERTPK)
{
// Server Certificate Verify
    ret rt;
    int lzero,sha;
    char scv[100+TLS_MAX_HASH];
    octad SCV={0,sizeof(scv),scv};
    char p[TLS_MAX_SIGNATURE_SIZE];
    octad P={0,sizeof(p),p};
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};

// TLS1.3 message that was signed
    OCT_append_byte(&SCV,32,64); // 64 spaces
    OCT_append_string(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_append_byte(&SCV,0,1);   // add 0 character
    OCT_append_octad(&SCV,H);    // add Transcript Hash 

    int len=SCVSIG->len;
    int rlen,slen,Int,der,ptr=0;

// probably need to support more cases
    switch (sigalg)
    {
    case RSA_PSS_RSAE_SHA256:
        sha=TLS_SHA256; // SHA256

        if (len==0x100)
        { // 2048 bit RSA
            return RSA_2048_PSS_RSAE_VERIFY(sha,&SCV,SCVSIG,CERTPK);
        }
        if (len==0x200)
        { // 4096 bit RSA
            return RSA_4096_PSS_RSAE_VERIFY(sha,&SCV,SCVSIG,CERTPK);
        }
        return false;
    case ECDSA_SECP256R1_SHA256:  // DER encoded !!
        sha=TLS_SHA256; // SHA256
        ptr=0;
        rt=parseByte(SCVSIG,ptr); der=rt.val;
        if (rt.err || der!=0x30) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen+2!=len) return false;

// get R
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
        rt=parseoctad(&R,0x20,SCVSIG,ptr); if (rt.err) return false;

// get S
        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen==0x21)
        { // one too big
            slen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseoctad(&S,0x20,SCVSIG,ptr); if (rt.err) return false;

        if (rlen<0x20 || slen<0x20) return false;

        return SECP256R1_ECDSA_VERIFY(sha,&SCV,&R,&S,CERTPK);

    case ECDSA_SECP384R1_SHA384:
        sha=TLS_SHA384;
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
        rt=parseoctad(&R,0x30,SCVSIG,ptr);  if (rt.err) return false;

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
        rt=parseoctad(&S,0x30,SCVSIG,ptr); if (rt.err) return false;

        if (rlen<0x30 || slen<0x30) return false;

        return SECP384R1_ECDSA_VERIFY(sha,&SCV,&R,&S,CERTPK);

    default :
#if VERBOSITY >= IO_DEBUG
        logger((char *)"WHOOPS - Unsupported signature type\n",NULL,0,NULL);
#endif
        return false;
    }
    return false;
}

