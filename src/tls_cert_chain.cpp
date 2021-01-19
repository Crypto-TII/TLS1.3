// TLS Server Certchain Code
#include "tls_cert_chain.h"
#include "tls_parse_octet.h"

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
            int alen,ac=X509_find_entity_property(&C, &X509_MN, ic, &alen);
            OCT_clear(&OWNER);
            OCT_jbytes(&OWNER,&C.val[ac],alen);

            if (OCT_comp(&OWNER,ISSUER))
            {
                pktype pt = X509_extract_public_key(&C, PUBKEY);

                if (st.type==pt.type && st.curve==pt.curve) 
                {
                    file.close();   
                    return true;
                }
            } 
        }
        file.close();   
    }
    return false;
}

void OUTPUT_CERT(octet *CERT)
{
    char b[TLS_MAX_SIGNED_CERT_B64];
    printf( "-----BEGIN CERTIFICATE----- ");
    printf("\n");
    OCT_tobase64(b,CERT);
    printf("%s\n",b);
    printf("-----END CERTIFICATE----- ");
    printf("\n");
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
    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
    OCT_clear(ISSUER);
    OCT_jbytes(ISSUER,&CERT->val[c],len);

    ic = X509_find_subject(CERT);
    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
    OCT_clear(SUBJECT);
    OCT_jbytes(SUBJECT,&CERT->val[c],len);
    return sg;
}

void SHOW_CERT_DETAILS(char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT)
{
    printf("\n%s\n",txt);
    printf("Signature is "); OCT_output(SIG);
    if (sg.type==X509_ECC)
    {
        printf("ECC signature ");
        if (sg.curve==USE_NIST256)
            printf("Curve is SECP256R1\n");
        if (sg.curve==USE_NIST384)
            printf("Curve is SECP384R1\n");
        if (sg.curve==USE_NIST521)
            printf("Curve is SECP521R1\n");
        if (sg.hash == X509_H256) printf("Hashed with SHA256\n");
        if (sg.hash == X509_H384) printf("Hashed with SHA384\n");
        if (sg.hash == X509_H512) printf("Hashed with SHA512\n");
    }
    if (sg.type==X509_RSA)
        printf("RSA signature of length %d\n",sg.curve);

    printf("Public key= %d ",PUBKEY->len); OCT_output(PUBKEY);
    if (pk.type==X509_ECC)
    {
        printf("ECC public key ");
        if (pk.curve==USE_NIST256)
            printf("Curve is SECP256R1\n");
        if (pk.curve==USE_NIST384)
            printf("Curve is SECP384R1\n");
        if (pk.curve==USE_NIST521)
            printf("Curve is SECP521R1\n");
    }
    if (pk.type==X509_RSA)
        printf("RSA public key of length %d\n",pk.curve);
    
    printf("Issuer is  ");OCT_output_string(ISSUER); printf("\n");
    printf("Subject is ");OCT_output_string(SUBJECT); printf("\n");
    printf("\n");
   
}

// Check signature on Certificate given signature type and public key
bool CHECK_CERT_SIG(pktype st,octet *CERT,octet *SIG, octet *PUBKEY)
{
    int sha=0;

    if (st.hash == X509_H256) sha = SHA256;
    if (st.hash == X509_H384) sha = SHA384;
    if (st.hash == X509_H512) sha = SHA512;
    if (st.hash == 0)
    {
        printf("Hash Function not supported\n");
        return 0;
    }

    if (st.type == 0)
    {
        printf("Unable to check cert signature\n");
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
        printf("SIG= \n");
        OCT_output(&R);
        OCT_output(&S);
        printf("\n");
        printf("ECC PUBLIC KEY= \n");
        OCT_output(PUBKEY);

        printf("Checking ECC Signature on Cert %d\n",st.curve);

        if (st.curve==USE_NIST256)
            res = NIST256::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (st.curve==USE_NIST384)
            res = NIST384::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (res != 0)
            printf("ECP Public Key is invalid!\n");
        else printf("ECP Public Key is Valid\n");

        if (st.curve==USE_NIST256)
            res=NIST256::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);
        if (st.curve==USE_NIST384)
            res=NIST384::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S);

        if (res!=0)
        {
            printf("***ECDSA Verification Failed\n");
            return false;
        } else {
            printf("ECDSA Signature/Verification succeeded \n");
            return true;
        }
    }

    if (st.type == X509_RSA)
    {
        int res;
        printf("st.curve= %d\n",st.curve);
        printf("SIG= %d\n",SIG->len);
        OCT_output(SIG);
        printf("\n");
        printf("RSA PUBLIC KEY= %d\n",PUBKEY->len);
        OCT_output(PUBKEY);

        printf("Checking RSA Signature on Cert %d\n",sha);
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
            printf("RSA Signature/Verification succeeded \n");
            return true;
        } else {
            printf("***RSA Verification Failed\n");
            return false;
        }
    }
    return false;
}

//extract server public key, and check validity of certificate chain
bool CHECK_CERT_CHAIN(octet *CERTCHAIN,octet *PUBKEY)
{
    int c,ptr=0;
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

    int len=parseInt24(CERTCHAIN,ptr); // get length of first (server) certificate
    parseOctet(&SCERT,len,CERTCHAIN,ptr); 

//printf("Server Cert= %d \n",SCERT.len);
//OUTPUT_CERT(&SCERT);

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions
    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,PUBKEY);
    st=GET_CERT_DETAILS(&SCERT,&CERT,&SIG,&ISSUER,&SUBJECT);   // get signature on Server Cert

    if (st.type==0)
    {
        printf("Unrecognised Signature Type\n");
        return false;
    }

    SHOW_CERT_DETAILS((char *)"Server certificate",PUBKEY,ca,&SIG,st,&ISSUER,&SUBJECT);

//    printf("cert.len= %d, ptr= %d\n",CERTCHAIN->len,ptr);
    len=parseInt24(CERTCHAIN,ptr); // get length of next certificate
    parseOctet(&SCERT,len,CERTCHAIN,ptr); 
//printf("Inter Cert= %d \n",SCERT.len);
//OUTPUT_CERT(&SCERT);

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions

    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,&CAKEY);  // get public key from Intermediate Cert
//    printf("Public Key of Intermediate Cert = %d ",CAKEY.len); OCT_output(&CAKEY);
//    printf("Signature on Server Cert = %d ",SIG.len); OCT_output(&SIG);

    if (CHECK_CERT_SIG(st,&CERT,&SIG,&CAKEY)) {
        printf("Intermediate Certificate Chain sig is OK\n");
    } else {
        printf("Intermediate Certificate Chain sig is NOT OK\n");
        return false;
    }

    stn=GET_CERT_DETAILS(&SCERT,&CERT,&SIG,&ISSUER,&SUBJECT);

    SHOW_CERT_DETAILS((char *)"Intermediate Certificate",&CAKEY,ca,&SIG,stn,&ISSUER,&SUBJECT);

//printf("Issuer= ");OCT_output_string(&ISSUER); printf("\n");

    if (FIND_ROOT_CA(&ISSUER,stn,&CAKEY)) {
        printf("\nPublic Key from root CA cert= "); OCT_output(&CAKEY);
 //       printf("type= %d, hash= %d, curve/len= %d\n",stn.type,stn.hash,stn.curve); 
    } else {
        printf("Root CA not found\n");
        return false;
    }

    if (CHECK_CERT_SIG(stn,&CERT,&SIG,&CAKEY)) {
        printf("Root Certificate sig is OK!!!!\n");
    } else {
        printf("Root Certificate sig is NOT OK\n");
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

