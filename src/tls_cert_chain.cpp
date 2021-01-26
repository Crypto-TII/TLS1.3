// TLS Server Certchain Code
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_logger.h"

// combine Common Name, Organisation Name and Unit Name
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

// given root issuer and public key type of signature, search through root CAs and return root public key
bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY)
{
    char sc[TLS_MAX_SIGNED_CERT_SIZE];  // maximum size for CA certs in bytes
    octet SC={0,sizeof(sc),sc};
    char c[TLS_MAX_CERT_SIZE];
    octet C={0,sizeof(c),c};
    char ca[TLS_X509_MAX_FIELD];
    octet CA={0,sizeof(ca),ca};
    char owner[TLS_X509_MAX_FIELD];
    octet OWNER={0,sizeof(owner),owner};
    char b[TLS_MAX_SIGNED_CERT_B64];  // maximum size for CA signed certs in base64
    ifstream file("ca-certificates.crt");

    if (file.is_open()) {
        string line;
        for (;;)
        {
            int i=0;
            if (!getline(file, line)) break;
            for (;;)
            {
                getline(file,line);
                if (line.c_str()[0]=='-') break;
                for (int j=0;j<64;j++)
                    b[i++]=line.c_str()[j];
                b[i]=0;
            }
            OCT_frombase64(&SC,b);
//printf("SC.len= %d %d\n",SC.len,i);

            int c = X509_extract_cert(&SC, &C);

            int ic = X509_find_issuer(&C);
            FULL_NAME(&OWNER,&C,ic);
            //int alen,ac=X509_find_entity_property(&C, &X509_MN, ic, &alen);
            //OCT_clear(&OWNER);
            //OCT_jbytes(&OWNER,&C.val[ac],alen);

            if (OCT_comp(&OWNER,ISSUER))
            {
                pktype pt = X509_extract_public_key(&C, PUBKEY);

                if (st.type==pt.type && st.curve==pt.curve) 
                {
//printf("Owner=  "); OCT_output_string(&OWNER); printf("\n");
//printf("Issuer= "); OCT_output_string(ISSUER); printf("\n");
                    file.close();   
                    return true;
                }
            } 
        }
        file.close();   
    }
    return false;
}

pktype GET_PUBLIC_KEY_FROM_SIGNED_CERT(octet *SCERT,octet *PUBLIC_KEY)
{
    char cert[TLS_MAX_CERT_SIZE];
    octet CERT={0,sizeof(cert),cert};
    X509_extract_cert(SCERT,&CERT);
    pktype pk=X509_extract_public_key(&CERT, PUBLIC_KEY);
    return pk;
}

// extract Cert, Signature, Issuer and Subject from Signed Cert
pktype GET_CERT_DETAILS(octet *SCERT,octet *CERT,octet *SIG,octet *ISSUER,octet *SUBJECT)
{
    int c,ic,len;

    pktype sg=X509_extract_cert_sig(SCERT,SIG);
    X509_extract_cert(SCERT,CERT);

    ic = X509_find_issuer(CERT);
    FULL_NAME(ISSUER,CERT,ic);

//    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
//    OCT_clear(ISSUER);
//    OCT_jbytes(ISSUER,&CERT->val[c],len);

    ic = X509_find_subject(CERT);
    FULL_NAME(SUBJECT,CERT,ic);
//    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
//    OCT_clear(SUBJECT);
//    OCT_jbytes(SUBJECT,&CERT->val[c],len);
    return sg;
}

// Check signature on Certificate given signature type and public key
bool CHECK_CERT_SIG(FILE *fp,pktype st,octet *CERT,octet *SIG, octet *PUBKEY)
{
    int sha=0;
    if (st.hash == X509_H256) sha = SHA256;
    if (st.hash == X509_H384) sha = SHA384;
    if (st.hash == X509_H512) sha = SHA512;
    if (st.hash == 0)
    {
        logger(fp,(char *)"Hash Function not supported\n",NULL,0,NULL);
        return 0;
    }
    if (st.type == 0)
    {
        logger(fp,(char *)"Unable to check cert signature\n",NULL,0,NULL);
        return false;
    }
    if (st.type == X509_ECC)
    {
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
        logger(fp,(char *)"SIG= \n",NULL,0,&R);
        logger(fp,(char *)"",NULL,0,&S);

        logger(fp,(char *)"\nECC PUBLIC KEY= \n",NULL,0,PUBKEY);

        logger(fp,(char *)"Checking ECC Signature on Cert ",(char *)"%d",st.curve,NULL);

        if (st.curve==USE_NIST256)
            res = NIST256::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (st.curve==USE_NIST384)
            res = NIST384::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (res != 0)
            logger(fp,(char *)"ECP Public Key is invalid!\n",NULL,0,NULL);
        else logger(fp,(char *)"ECP Public Key is Valid\n",NULL,0,NULL);

        if (st.curve==USE_NIST256)
            res=NIST256::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);
        if (st.curve==USE_NIST384)
            res=NIST384::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);

        if (res!=0)
        {
            logger(fp,(char *)"***ECDSA Verification Failed\n",NULL,0,NULL);
            return false;
        } else {
            logger(fp,(char *)"ECDSA Signature/Verification succeeded \n",NULL,0,NULL);
            return true;
        }
    }
    if (st.type == X509_RSA)
    {
        int res;
        logger(fp,(char *)"st.curve= ",(char *)"%d",st.curve,NULL);
        logger(fp,(char *)"SIG= ",NULL,0,SIG);
        logger(fp,(char *)"\nRSA PUBLIC KEY= ",NULL,0,PUBKEY);

        logger(fp,(char *)"Checking RSA Signature on Cert \n",NULL,0,NULL);
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
//printf("P1= "); OCT_output(&P1);
//printf("P2= "); OCT_output(&P2);

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
            logger(fp,(char *)"RSA Signature/Verification succeeded \n",NULL,0,NULL);
            return true;
        } else {
            logger(fp,(char *)"***RSA Verification Failed\n",NULL,0,NULL);
            return false;
        }
    }
    return false;
}

//extract server public key, and check validity of certificate chain
bool CHECK_CERT_CHAIN(FILE *fp,octet *CERTCHAIN,octet *PUBKEY)
{
    ret r;
    int len,c,ptr=0;
    bool self_signed;
    pktype st,ca,stn;
    char sig[TLS_MAX_SIGNATURE_SIZE];  // signature on certificate
    octet SIG={0,sizeof(sig),sig};
    char scert[TLS_MAX_SIGNED_CERT_SIZE]; // signed certificate
    octet SCERT={0,sizeof(scert),scert};
    char cert[TLS_MAX_CERT_SIZE];  // certificate
    octet CERT={0,sizeof(cert),cert};
    char cakey[TLS_MAX_PUB_KEY_SIZE];  // Public Key from Cert
    octet CAKEY = {0, sizeof(cakey), cakey};
    char issuer[TLS_X509_MAX_FIELD];  
    octet ISSUER={0,sizeof(issuer),issuer};
    char subject[TLS_X509_MAX_FIELD];
    octet SUBJECT={0,sizeof(subject),subject};

    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false;// get length of first (server) certificate
    r=parseOctet(&SCERT,len,CERTCHAIN,ptr); if (r.err) return false;

    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions
    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,PUBKEY);

    st=GET_CERT_DETAILS(&SCERT,&CERT,&SIG,&ISSUER,&SUBJECT);   // get signature on Server Cert

    if (st.type==0)
    {
        logger(fp,(char *)"Unrecognised Signature Type\n",NULL,0,NULL);
        return false;
    }

    logCertDetails(fp,(char *)"Server certificate",PUBKEY,ca,&SIG,st,&ISSUER,&SUBJECT);

    r=parseInt24(CERTCHAIN,ptr); len=r.val; if (r.err) return false; // get length of next certificate
    r=parseOctet(&SCERT,len,CERTCHAIN,ptr); if (r.err) return false;


    r=parseInt16(CERTCHAIN,ptr); len=r.val; if (r.err) return false;
    ptr+=len;   // skip certificate extensions

    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,&CAKEY);  // get public key from Intermediate Cert

    if (CHECK_CERT_SIG(fp,st,&CERT,&SIG,&CAKEY)) {
        logger(fp,(char *)"Intermediate Certificate Chain sig is OK\n",NULL,0,NULL);
    } else {
        logger(fp,(char *)"Intermediate Certificate Chain sig is NOT OK\n",NULL,0,NULL);
        return false;
    }

    stn=GET_CERT_DETAILS(&SCERT,&CERT,&SIG,&ISSUER,&SUBJECT);

    //logCert(fp,&SCERT);

    logCertDetails(fp,(char *)"Intermediate Certificate",&CAKEY,ca,&SIG,stn,&ISSUER,&SUBJECT);

    if (FIND_ROOT_CA(&ISSUER,stn,&CAKEY)) {
        logger(fp,(char *)"\nPublic Key from root CA cert= ",NULL,0,&CAKEY);
    } else {
        logger(fp,(char *)"Root CA not found\n",NULL,0,NULL);
        return false;
    }

    if (CHECK_CERT_SIG(fp,stn,&CERT,&SIG,&CAKEY)) {
        logger(fp,(char *)"Root Certificate sig is OK!!!!\n",NULL,0,NULL);
    } else {
        logger(fp,(char *)"Root Certificate sig is NOT OK\n",NULL,0,NULL);
        return false;
    }

    return true;
}

// check that SCVSIG is digital signature (using sigalg algorithm) of some TLS1.3 specific message+transcript hash, as verified by Server Certificate public key CERTPK
// Only supports MUST supported algorithms.
// RFC8446:     "A TLS-compliant application MUST support digital signatures with
//              rsa_pkcs1_sha256 (for certificates), rsa_pss_rsae_sha256 (for
//              CertificateVerify and certificates), and ecdsa_secp256r1_sha256."

bool IS_SERVER_CERT_VERIFY(FILE *fp,int sigalg,octet *SCVSIG,octet *H,octet *CERTPK)
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
        rt=parseByte(SCVSIG,ptr); der=rt.val;
        if (rt.err || der!=0x30) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen+2!=len) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); rlen=rt.val;
        if (rt.err) return false;
        if (rlen==0x21)
        {
            rlen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&R,0x20,SCVSIG,ptr); if (rt.err) return false;

        rt=parseByte(SCVSIG,ptr); Int=rt.val;
        if (rt.err || Int!=0x02) return false;
        rt=parseByte(SCVSIG,ptr); slen=rt.val;
        if (rt.err || slen==0x21)
        {
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
        { // there must be a leading zero
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
        { // there must be a leading zero
            slen--;
            rt=parseByte(SCVSIG,ptr); lzero=rt.val;
            if (rt.err || lzero!=0) return false;
        }
        rt=parseOctet(&S,0x30,SCVSIG,ptr); if (rt.err) return false;

        if (rlen<0x30 || slen<0x30) return false;

        if (NIST384::ECP_VP_DSA(sha, CERTPK, &SCV, &R, &S) == 0)
        return true;

    default :
        logger(fp,(char *)"WHOOPS - Unsupported signature type\n",NULL,0,NULL);
        return false;
    }
    return false;
}

