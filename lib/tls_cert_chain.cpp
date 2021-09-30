// TLS1.3 Certificate Processing Code

#include "tls_cert_chain.h"

// combine Common Name, Organisation Name and Unit Name to make unique determination
static void createFullName(octad *FN,octad *CERT,int ic)
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
static pktype getPublicKeyFromCert(octad *CERT,octad *PUBLIC_KEY)
{
    pktype pk=X509_extract_public_key(CERT, PUBLIC_KEY);  // pull out its public key
    return pk;
}

static bool checkHostnameInCert(octad *CERT,char *hostname)
{
    int len;
    int ic=X509_find_extensions(CERT);
    int c=X509_find_extension(CERT,&X509_AN,ic,&len);
    return (bool)X509_find_alt_name(CERT,c,hostname);
}

static bool checkCertValidity(octad *CERT)
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

static bool findRootCA(octad* ISSUER,pktype st,octad *PUBKEY)
{
    char ca[TLS_X509_MAX_FIELD];
    octad CA={0,sizeof(ca),ca};
    char owner[TLS_X509_MAX_FIELD];
    octad OWNER={0,sizeof(owner),owner};
    //char sc[TLS_MAX_ROOT_CERT_SIZE];  // server certificate
    char b[TLS_MAX_ROOT_CERT_B64];  // maximum size for CA root signed certs in base64
    octad SC={0,sizeof(b),b};       // optimization - share memory
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
        createFullName(&OWNER,&SC,ic);

        if (!checkCertValidity(&SC))
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
static pktype stripDownCert(octad *CERT,octad *SIG,octad *ISSUER,octad *SUBJECT)
{
    int c,ic,len;

    pktype sg=X509_extract_cert_sig(CERT,SIG);
    X509_extract_cert(CERT,CERT);

    ic = X509_find_issuer(CERT);
    createFullName(ISSUER,CERT,ic);

    ic = X509_find_subject(CERT);
    createFullName(SUBJECT,CERT,ic);

    return sg;
}

// Check signature on Certificate given signature type and public key
static bool checkCertSig(pktype st,octad *CERT,octad *SIG, octad *PUBKEY)
{
// determine signature algorithm
    int sha=0;
    bool res=false;

// determine certificate signature type, by parsing pktype
    int sigAlg=0;
    if (st.type== X509_ECC && st.hash==X509_H256 && st.curve==USE_NIST256)
        sigAlg = ECDSA_SECP256R1_SHA256;
    if (st.type== X509_ECC && st.hash==X509_H384 && st.curve==USE_NIST384)
        sigAlg = ECDSA_SECP384R1_SHA384;
    if (st.type== X509_ECD && st.curve==USE_C25519)
        sigAlg = ED25519;
    if (st.type== X509_RSA && st.hash==X509_H256)
        sigAlg = RSA_PKCS1_SHA256;
    if (st.type== X509_RSA && st.hash==X509_H384)
        sigAlg = RSA_PKCS1_SHA384;
    if (st.type== X509_RSA && st.hash==X509_H512)
        sigAlg = RSA_PKCS1_SHA512;

    if (sigAlg == 0)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Unable to check cert signature\n",NULL,0,NULL);
#endif
        return false;
    }

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Signature  = ",NULL,0,SIG);
    logger((char *)"Public key = ",NULL,0,PUBKEY);
    logger((char *)"Checking Signature on Cert \n",NULL,0,NULL);
    logSigAlg(sigAlg);
#endif

    res=SAL_tlsSignatureVerify(sigAlg,CERT,SIG,PUBKEY); 

    if (res)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Cert Signature Verification succeeded \n",NULL,0,NULL);
#endif
        return true;
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Cert Signature Verification Failed\n",NULL,0,NULL);
#endif
        return false;
    }
}

// Read in raw certificate chain from file, and serialize it for transmission
// Read in client private key from .pem file
int getClientPrivateKeyandCertChain(int nccsalgs,int *csigAlgs,octad *PRIVKEY,octad *CERTCHAIN)
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

// figure out kind of signature client can apply - will be tested against client capabilities
// Note that no hash type is specified - its just a private key, no algorithm specified
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
        if (kind==csigAlgs[i]) return kind;
    }

    return 0;
}

// extract server public key, and check validity of certificate chain
// ensures that the hostname is valid.
// Assumes simple chain Server Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
int checkServerCertChain(octad *CERTCHAIN,char *hostname,octad *PUBKEY)
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

    char pk[TLS_MAX_PUB_KEY_SIZE];  // Public Key 
    octad PK = {0, sizeof(pk), pk};

    char issuer[TLS_X509_MAX_FIELD];  
    octad ISSUER={0,sizeof(issuer),issuer};
    char subject[TLS_X509_MAX_FIELD];
    octad SUBJECT={0,sizeof(subject),subject};

// Extract and process Server Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return BAD_CERT_CHAIN;// get length of first (server) certificate
    r=parseoctadptr(&SCERT,len,CERTCHAIN,ptr); if (r.err) return BAD_CERT_CHAIN;

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return BAD_CERT_CHAIN;
    ptr+=len;   // skip certificate extensions

    sst=stripDownCert(&SCERT,&SSIG,&ISSUER,&SUBJECT);    // extract signature
    spt=getPublicKeyFromCert(&SCERT,PUBKEY);           // extract  public key

    if (!checkHostnameInCert(&SCERT,hostname))
    { // Check that certificate covers the server URL
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Hostname not found in certificate\n",NULL,0,NULL);
#endif
        if (strcmp(hostname,"localhost")!=0) return BAD_CERT_CHAIN;
    }
    if (!checkCertValidity(&SCERT))
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Certificate has expired\n",NULL,0,NULL);
#endif
        return CERT_OUTOFDATE;
    }

    if (sst.type==0)
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Unrecognised Signature Type\n",NULL,0,NULL);
#endif
        return BAD_CERT_CHAIN;
    }
#if VERBOSITY >= IO_DEBUG
    logCertDetails((char *)"\nParsing Server certificate\n",PUBKEY,spt,&SSIG,sst,&ISSUER,&SUBJECT);
#endif
    if (OCT_compare(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return 0;   // not fatal for development purposes
    }

// Extract and process Intermediate Cert
    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return BAD_CERT_CHAIN; // get length of next certificate
    r=parseoctadptr(&ICERT,len,CERTCHAIN,ptr); if (r.err) return BAD_CERT_CHAIN;

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return BAD_CERT_CHAIN;
    ptr+=len;   // skip certificate extensions

#if VERBOSITY >= IO_PROTOCOL
    if (ptr<CERTCHAIN->len)
        logger((char *)"Warning - there are unprocessed Certificates in the Chain\n",NULL,0,NULL);
#endif

    ist=stripDownCert(&ICERT,&ISIG,&ISSUER,&SUBJECT);
    ipt=getPublicKeyFromCert(&ICERT,&PK);

    if (!checkCertValidity(&ICERT))
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate has expired\n",NULL,0,NULL);
#endif
        return CERT_OUTOFDATE;
    }

#if VERBOSITY >= IO_DEBUG
    logCertDetails((char *)"Parsing Intermediate certificate\n",&PK,ipt,&ISIG,ist,&ISSUER,&SUBJECT);
#endif
    if (checkCertSig(sst,&SCERT,&SSIG,&PK)) {  // Check server cert signature with inter cert public key
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate Chain sig is OK\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Intermediate Certificate Chain sig is NOT OK\n",NULL,0,NULL);
#endif
        return BAD_CERT_CHAIN;
    }

    if (OCT_compare(&ISSUER,&SUBJECT))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - Self signed Cert\n",NULL,0,NULL);
#endif
        return 0;   // not fatal for development purposes
    }

// Find Root of Trust
// Find root certificate public key
    if (findRootCA(&ISSUER,ist,&PK)) {
#if VERBOSITY >= IO_DEBUG        
        logger((char *)"\nPublic Key from root cert= ",NULL,0,&PK);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate not found\n",NULL,0,NULL);
#endif
        return CA_NOT_FOUND;
    }

    if (checkCertSig(ist,&ICERT,&ISIG,&PK)) {  // Check inter cert signature with root cert public key
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate sig is OK\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate sig is NOT OK\n",NULL,0,NULL);
#endif
        return BAD_CERT_CHAIN;
    }
    return 0;
}

