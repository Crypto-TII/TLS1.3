//
// TLS1.3 X509 Certificate Processing Code
//

#include "tls_cert_chain.h"

#include <sys/time.h>

static unsigned long seconds()
{
    unsigned long seconds;
    struct timeval stop_watch;
    gettimeofday(&stop_watch, NULL);
    seconds=stop_watch.tv_sec;
    return seconds;
}

static int toint(char f,char s) {
    return (int)(f-'0')*10+s-'0';
}

// create tm structure from extracted datetime
static void mystrptime(char *c,struct tm* tms)
{
    int year,month,day,hour,minute,second;
    tms->tm_year=100+toint(c[0],c[1]);
    tms->tm_mon=toint(c[2],c[3])-1;
    tms->tm_mday=toint(c[4],c[5]);
    tms->tm_hour=toint(c[6],c[7]);
    tms->tm_min=toint(c[8],c[9]);
    tms->tm_sec=toint(c[10],c[11]);
};

static unsigned long epoch_seconds(char *certtime)
{
    struct tm tms{};
    mystrptime(certtime,&tms);
    return (unsigned long)mktime(&tms);
}

// extract Distinguished Name
static void createFullName(octad *FN,octad *CERT,int ic,int len)
{
    OCT_kill(FN);
    OCT_append_bytes(FN,&CERT->val[ic],len);

/*
    int c,len;
    OCT_kill(FN);
    c=X509_find_entity_property(CERT,&X509_MN,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len);
    OCT_append_byte(FN,'/',1); // spacer
    c=X509_find_entity_property(CERT,&X509_ON,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len);
    OCT_append_byte(FN,'/',1);
    c=X509_find_entity_property(CERT,&X509_UN,ic,&len);
    OCT_append_bytes(FN,&CERT->val[c],len); */
}

// read a line of base64
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

// extract host name
static bool checkHostnameInCert(octad *CERT,char *hostname)
{
    int len;
    int ic=X509_find_extensions(CERT);
    int c=X509_find_extension(CERT,&X509_AN,ic,&len);
    return (bool)X509_find_alt_name(CERT,c,hostname);
}

// Check for certificate validity
static bool checkCertNotExpired(octad *CERT)
{
    unsigned long begin,end,now;
    int ic = X509_find_validity(CERT);
    int cs = X509_find_start_date(CERT, ic);
    begin=epoch_seconds(&CERT->val[cs]);
    int ce = X509_find_expiry_date(CERT, ic);
    end=epoch_seconds(&CERT->val[ce]);
    now=seconds();
    //printf("cert time %lx %lx %lx\n",begin,end,now);
    if (now>begin && now<end)
        return true;
    return false;

    //int year=2000+(CERT->val[c]-'0')*10 +CERT->val[c+1]-'0';
    //if (year<THIS_YEAR) return false;
    //return true;
}

// given root issuer and public key type of signature, search through root CAs and return root public key
// This is a simple linear search through CA certificates found in the ca-certificates.crt file (borrowed from Ubuntu)
// This file should be in Read-Only-Memory

static bool findRootCA(octad* ISSUER,pktype st,octad *PUBKEY)
{
    char owner[TLS_X509_MAX_FIELD];
    octad OWNER={0,sizeof(owner),owner};
#ifdef SHALLOW_STACK
    char *b=(char *)malloc(TLS_MAX_CERT_B64);
    octad SC={0,TLS_MAX_CERT_B64,b};        // optimization - share memory - can convert from base64 to binary in place
#else
    char b[TLS_MAX_CERT_B64];                // maximum size for CA root signed certs in base64
    octad SC={0,sizeof(b),b};                // optimization - share memory - can convert from base64 to binary in place
#endif
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
        X509_extract_cert(&SC, &SC);  // extract Cert from Signed Cert

        int ic = X509_find_issuer(&SC,&len);
        createFullName(&OWNER,&SC,ic,len);

        if (!checkCertNotExpired(&SC))
        { // Its expired!
            continue;
        }

        if (OCT_compare(&OWNER,ISSUER))
        {
            pktype pt = X509_extract_public_key(&SC, PUBKEY);
            if (st.type==pt.type || st.curve==pt.curve) 
            { // found CA cert 
                if (st.type==X509_PQ || st.type==X509_HY || st.curve==pt.curve)
                {
#ifdef SHALLOW_STACK
                    free(b);
#endif
//        char buff[256];
//        OCT_output_base64(&OWNER,256,buff);
//        printf("BASE64 DN = %s\n",buff);

                    return true;
                }
            }
        } 
    }
#ifdef SHALLOW_STACK
    free(b);
#endif
    return false;  // couldn't find it
}

// strip signature off certificate. Return signature type
static pktype stripDownCert(octad *CERT,octad *SIG,octad *ISSUER,octad *SUBJECT)
{
    int ic,len;

    pktype sg=X509_extract_cert_sig(CERT,SIG);
    X509_extract_cert(CERT,CERT);  // modifies CERT which is in the IO buffer!

    ic = X509_find_issuer(CERT,&len);
    createFullName(ISSUER,CERT,ic,len);

    ic = X509_find_subject(CERT,&len);
    createFullName(SUBJECT,CERT,ic,len);

    return sg;
}

// Check signature on Certificate given signature type and public key
static bool checkCertSig(pktype st,octad *CERT,octad *SIG, octad *PUBKEY)
{
// determine signature algorithm
    bool res=false;

    log(IO_DEBUG,(char *)"Signature  = ",NULL,0,SIG);
    log(IO_DEBUG,(char *)"Public key = ",NULL,0,PUBKEY);
    log(IO_DEBUG,(char *)"Checking Signature on Cert \n",NULL,0,NULL);

// determine certificate signature type, by parsing pktype
    if (st.type== X509_ECC && st.hash==X509_H256 && st.curve==USE_NIST256)
        res=SAL_tlsSignatureVerify(ECDSA_SECP256R1_SHA256,CERT,SIG,PUBKEY);
    if (st.type== X509_ECC && st.hash==X509_H384 && st.curve==USE_NIST384)
        res=SAL_tlsSignatureVerify(ECDSA_SECP384R1_SHA384,CERT,SIG,PUBKEY);
    if (st.type== X509_ECD && st.curve==USE_ED25519)
        res=SAL_tlsSignatureVerify(ED25519,CERT,SIG,PUBKEY);
    if (st.type== X509_ECD && st.curve==USE_ED448)
        res=SAL_tlsSignatureVerify(ED448,CERT,SIG,PUBKEY);
    if (st.type== X509_RSA && st.hash==X509_H256)
        res=SAL_tlsSignatureVerify(RSA_PKCS1_SHA256,CERT,SIG,PUBKEY);
    if (st.type== X509_RSA && st.hash==X509_H384)
        res=SAL_tlsSignatureVerify(RSA_PKCS1_SHA384,CERT,SIG,PUBKEY);
    if (st.type== X509_RSA && st.hash==X509_H512)
        res=SAL_tlsSignatureVerify(RSA_PKCS1_SHA512,CERT,SIG,PUBKEY);
    if (st.type== X509_PQ)
        res=SAL_tlsSignatureVerify(MLDSA65,CERT,SIG,PUBKEY);

// probably deepest into the stack at this stage.... (especially for MLDSA)

    if (st.type==X509_HY)
    {
        octad FPUB={65,65,PUBKEY->val};
        octad SPUB={PUBKEY->len-65,PUBKEY->len-65,&PUBKEY->val[65]};
        octad FSIG={64,64,SIG->val};
        octad SSIG={SIG->len-64,SIG->len-64,&SIG->val[64]};
        res = SAL_tlsSignatureVerify(ECDSA_SECP256R1_SHA384,CERT,&FSIG,&FPUB) && SAL_tlsSignatureVerify(MLDSA44,CERT,&SSIG,&SPUB);
    }

    if (res)
    {
        log(IO_DEBUG,(char *)"Cert Signature Verification succeeded \n",NULL,0,NULL);
        return true;
    } else {
        log(IO_DEBUG,(char *)"Cert Signature Verification Failed\n",NULL,0,NULL);
        return false;
    }
}

// Check certificate has not expired
// Detach signature from certificate
// Check if self-signed
// Check signature and public keys are supported types
// Check subject of this certificate is issuer of previous certificate in the chain
// output signature and public key, and issuer of this certificate
static int parseCert(octad *SCERT,pktype &sst,octad *SSIG,octad *PREVIOUS_ISSUER,pktype &spt,octad *PUBKEY)
{
    char subject[TLS_X509_MAX_FIELD];
    octad SUBJECT={0,sizeof(subject),subject};
    char issuer[TLS_X509_MAX_FIELD];  
    octad ISSUER={0,sizeof(issuer),issuer};

    sst=stripDownCert(SCERT,SSIG,&ISSUER,&SUBJECT);    // break down Cert and extract signature

    if (!checkCertNotExpired(SCERT)) {
        log(IO_DEBUG,(char *)"Certificate has expired\n",NULL,0,NULL);
        return  CERT_OUTOFDATE;
    }
    if (sst.type==0)
    {
        log(IO_DEBUG,(char *)"Unrecognised Signature Type\n",NULL,0,NULL);
        return BAD_CERT_CHAIN;
    }

    spt=getPublicKeyFromCert(SCERT,PUBKEY);
    logCertDetails(PUBKEY,spt,SSIG,sst,&ISSUER,&SUBJECT);

    if (spt.type==0)
    {
        log(IO_DEBUG,(char *)"Unrecognised Public key Type\n",NULL,0,NULL);
        return BAD_CERT_CHAIN;
    }

    if (OCT_compare(&ISSUER,&SUBJECT))
    { //self-signed certificate
        log(IO_DEBUG,(char *)"Self signed Cert\n",NULL,0,NULL);
        return SELF_SIGNED_CERT;   // not necessarily fatal
    }

    if (PREVIOUS_ISSUER->len!=0)
    { // there was one
        if (!OCT_compare(PREVIOUS_ISSUER,&SUBJECT))
        { // Is subject of this cert the issuer of the previous cert?
            log(IO_DEBUG,(char *)"Subject of this certificate is not issuer of prior certificate\n",NULL,0,NULL);
            return BAD_CERT_CHAIN;
        }
    }
    OCT_copy(PREVIOUS_ISSUER,&ISSUER); // update issuer

    return 0;
}

// extract server public key, and check validity of certificate chain
// ensures that the hostname is valid.
// Assumes simple chain Server Cert->Intermediate Cert->CA cert
// CA cert not read from chain (if its even there). 
// Search for issuer of Intermediate Cert in cert store 
int checkServerCertChain(octad *CERTCHAIN,char *hostname,int cert_type,octad *PUBKEY,octad *SERVER_SIG)
{
    ret r;
    int rtn,len,ptr=0;
    pktype sst,ist,spt,ipt;

// Clever re-use of memory - use pointers into cert chain rather than extracting certs
    octad SERVER_CERT;  // server certificate
    SERVER_CERT.len=0;
    octad INTER_CERT;  // signature on intermediate certificate
    INTER_CERT.len=0;

    char issuer[TLS_X509_MAX_FIELD];  
    octad ISSUER={0,sizeof(issuer),issuer};

// Extract and process Server Cert
    r=parseInt(CERTCHAIN,3,ptr); len=r.val; if (r.err) return r.err; // get length of first (server) certificate
    if (len==0)
        return EMPTY_CERT_CHAIN;

    r=parseoctadptr(&SERVER_CERT,len,CERTCHAIN,ptr); if (r.err) return r.err;

    if (cert_type==RAW_PUBLIC_KEY) { // its not a certificate, its a raw public key. We agreed that this was OK.
        X509_get_public_key(&SERVER_CERT,PUBKEY);
        return 0;  // NOTE no confirmation of identity
    }

    r=parseInt(CERTCHAIN,2,ptr); len=r.val; if (r.err) return r.err;
    ptr+=len;   // skip certificate extensions

// Check and parse Server Cert
    rtn=parseCert(&SERVER_CERT,sst,SERVER_SIG,&ISSUER,spt,PUBKEY);
    if (rtn != 0) {
        if (rtn==SELF_SIGNED_CERT)
        {
            if (!checkCertSig(sst,&SERVER_CERT,SERVER_SIG,PUBKEY)) {
                return BAD_CERT_CHAIN;
            }
        } else {
            return rtn;
        }
    }

// Confirm Identity - public key is associated with this hostname
    if (!checkHostnameInCert(&SERVER_CERT,hostname) && strcmp(hostname,"localhost")!=0)
    { // Check that certificate covers the server URL
        log(IO_PROTOCOL,(char *)"Hostname NOT found in certificate\n",NULL,0,NULL);
#ifdef CHECK_NAME_IN_CERT
        return BAD_CERT_CHAIN;
#endif
    }

    if (rtn==SELF_SIGNED_CERT) 
    {
#ifdef ALLOW_SELF_SIGNED
        log(IO_PROTOCOL,(char *)"Self-signed Certificate allowed\n",NULL,0,NULL);
        return 0;  // If self-signed, thats the end of the chain. And for development its acceptable
#else
        return rtn;
#endif
    }
    if (ptr==CERTCHAIN->len)
    {
        log(IO_DEBUG,(char *)"Non-self-signed Chain of length 1 ended unexpectedly\n",NULL,0,NULL);
        return BAD_CERT_CHAIN;
    }

// Extract and process Intermediate Cert
    r=parseInt(CERTCHAIN,3,ptr); len=r.val; if (r.err) return r.err; // get length of next certificate
    if (len==0)
        return EMPTY_CERT_CHAIN;

    r=parseoctadptr(&INTER_CERT,len,CERTCHAIN,ptr); if (r.err) return r.err;

    r=parseInt(CERTCHAIN,2,ptr); len=r.val; if (r.err) return r.err;
    ptr+=len;   // skip certificate extensions

    if (ptr<CERTCHAIN->len)
        log(IO_DEBUG,(char *)"Warning - there are unprocessed Certificates in the Chain\n",NULL,0,NULL);

#ifdef SHALLOW_STACK
    octad INTER_SIG={0,TLS_MAX_SIGNATURE_SIZE,(char *)malloc(TLS_MAX_SIGNATURE_SIZE)};
    octad PK = {0, TLS_MAX_SIG_PUB_KEY_SIZE, (char *)malloc(TLS_MAX_SIG_PUB_KEY_SIZE)};
#else
    char inter_sig[TLS_MAX_SIGNATURE_SIZE];  // signature on intermediate certificate
    octad INTER_SIG={0,sizeof(inter_sig),inter_sig};
    char pk[TLS_MAX_SIG_PUB_KEY_SIZE];  // Public Key 
    octad PK = {0, sizeof(pk), pk};
#endif

// Check and parse Intermediate Cert
    rtn=parseCert(&INTER_CERT,ist,&INTER_SIG,&ISSUER,ipt,&PK);
    if (rtn != 0) {
#ifdef SHALLOW_STACK
        free(INTER_SIG.val); free(PK.val);
#endif
        return BAD_CERT_CHAIN;
    }

    if (!checkCertSig(sst,&SERVER_CERT,SERVER_SIG,&PK)) {  // Check intermediate signature on Server's certificate 
        log(IO_DEBUG,(char *)"Server Certificate sig is NOT OK\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(INTER_SIG.val); free(PK.val);
#endif
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,(char *)"Server Certificate sig is OK\n",NULL,0,NULL);

// Find Root of Trust
// Find root certificate public key
    if (!findRootCA(&ISSUER,ist,&PK)) {
        log(IO_DEBUG,(char *)"Root Certificate not found\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(INTER_SIG.val); free(PK.val);
#endif
        return CA_NOT_FOUND;
    }       
    log(IO_DEBUG,(char *)"\nPublic Key from root cert= ",NULL,0,&PK);

    if (!checkCertSig(ist,&INTER_CERT,&INTER_SIG,&PK)) {  // Check signature on intermediate cert with root cert public key
        log(IO_DEBUG,(char *)"Root Certificate sig is NOT OK\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(INTER_SIG.val); free(PK.val);
#endif
        return BAD_CERT_CHAIN;
    }
    log(IO_DEBUG,(char *)"Root Certificate sig is OK\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
    free(INTER_SIG.val); free(PK.val);
#endif
    return 0;
}

