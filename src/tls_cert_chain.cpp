// TLS1.3 Certificate Processing Code

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

    ic = X509_find_subject(CERT);
    FULL_NAME(SUBJECT,CERT,ic);

    return sg;
}

// Check signature on Certificate given signature type and public key
static bool CHECK_CERT_SIG(pktype st,octad *CERT,octad *SIG, octad *PUBKEY)
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
    logger((char *)"SIG = \n",NULL,0,SIG);
    logger((char *)"\nPUBLIC KEY= \n",NULL,0,PUBKEY);
    logger((char *)"Checking Signature on Cert \n",NULL,0,NULL);
    logSigAlg(sigAlg);
#endif

    res=CERT_SIGNATURE_VERIFY(sigAlg,CERT,SIG,PUBKEY); 


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
        logger((char *)"Root Certificate sig is OK\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Root Certificate sig is NOT OK\n",NULL,0,NULL);
#endif
        return false;
    }
    return true;
}

static void parse_in_ecdsa_sig(int sha,octad *CCVSIG)
{ // parse ECDSA signature into DER encoded (r,s) form
    char c[TLS_MAX_ECC_FIELD];
    octad C={0,sizeof(c),c};
    char d[TLS_MAX_ECC_FIELD];
    octad D={0,sizeof(d),d};
    int len,clen=sha;
    bool cinc=false;
    bool dinc=false;

    C.len=D.len=clen;
    for (int i=0;i<clen;i++)
    {
        C.val[i]=CCVSIG->val[i];
        D.val[i]=CCVSIG->val[clen+i];
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

// Create Client Cert Verify message, a digital signature using KEY on some TLS1.3 specific message+transcript hash
void CREATE_CLIENT_CERT_VERIFIER(int sigAlg,octad *H,octad *KEY,octad *CCVSIG)
{
    char ccv[100+TLS_MAX_HASH];
    octad CCV={0,sizeof(ccv),ccv};
// create TLS1.3 message to be signed
    OCT_append_byte(&CCV,32,64); // 64 spaces
    OCT_append_string(&CCV,(char *)"TLS 1.3, client CertificateVerify");  // 33 chars
    OCT_append_byte(&CCV,0,1);   // add 0 character
    OCT_append_octad(&CCV,H);    // add Transcript Hash 

    TLS_SIGNATURE_SIGN(sigAlg,KEY,&CCV,CCVSIG);

// adjustment for ECDSA signatures
    if (sigAlg==ECDSA_SECP256R1_SHA256)
        parse_in_ecdsa_sig(TLS_SHA256,CCVSIG);
    if (sigAlg==ECDSA_SECP384R1_SHA384)
        parse_in_ecdsa_sig(TLS_SHA384,CCVSIG);

    return;
}

static bool parse_out_ecdsa_sig(int sha,octad *SCVSIG)
{ // parse out DER encoded (r,s) ECDSA signature into a single SIG 
    ret rt;
    int lzero,der,rlen,slen,Int,ptr=0;
    int len=SCVSIG->len;
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};

    rt=parseByte(SCVSIG,ptr); der=rt.val;
    if (rt.err || der!=0x30) return false;
    rt=parseByte(SCVSIG,ptr); slen=rt.val;
    if (rt.err || slen+2!=len) return false;

// get R
    rt=parseByte(SCVSIG,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseByte(SCVSIG,ptr); rlen=rt.val;
    if (rt.err) return false;
    if (rlen==sha+1)
    { // one too big
        rlen--;
        rt=parseByte(SCVSIG,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&R,sha,SCVSIG,ptr); if (rt.err) return false;

// get S
    rt=parseByte(SCVSIG,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseByte(SCVSIG,ptr); slen=rt.val;
    if (rt.err || slen==sha+1)
    { // one too big
        slen--;
        rt=parseByte(SCVSIG,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&S,sha,SCVSIG,ptr); if (rt.err) return false;

    if (rlen<sha || slen<sha) return false;

    OCT_copy(SCVSIG,&R);
    OCT_append_octad(SCVSIG,&S);
    return true;
}

// check that SCVSIG is digital signature (using sigAlg algorithm) of some TLS1.3 specific message+transcript hash, 
// as verified by Server Certificate public key CERTPK

bool IS_SERVER_CERT_VERIFY(int sigAlg,octad *SCVSIG,octad *H,octad *CERTPK)
{
// Server Certificate Verify
    ret rt;
    int lzero,sha;
    char scv[100+TLS_MAX_HASH];
    octad SCV={0,sizeof(scv),scv};
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};
    char sig[2*TLS_MAX_ECC_FIELD];
    octad SIG={0,sizeof(sig),sig};

// TLS1.3 message that was signed
    OCT_append_byte(&SCV,32,64); // 64 spaces
    OCT_append_string(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_append_byte(&SCV,0,1);   // add 0 character
    OCT_append_octad(&SCV,H);    // add Transcript Hash 

// Special case processing required here for ECDSA signatures -  SCVSIG is modified
    if (sigAlg==ECDSA_SECP256R1_SHA256) {
        if (!parse_out_ecdsa_sig(TLS_SHA256,SCVSIG)) return false;
    }
    if (sigAlg==ECDSA_SECP384R1_SHA384) {
        if (!parse_out_ecdsa_sig(TLS_SHA384,SCVSIG)) return false;
    } 

    return TLS_SIGNATURE_VERIFY(sigAlg,&SCV,SCVSIG,CERTPK);
}
