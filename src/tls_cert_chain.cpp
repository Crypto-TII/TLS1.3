// TLS Server Certchain Code
#include "tls_cert_chain.h"
#include "tls_parse_octet.h"

// given root issuer and public key type of signature, search through root CAs and return root public key
bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY)
{
    char sc[2048];  // maximum size for CA certs in bytes
    octet SC={0,sizeof(sc),sc};
    char c[2048];
    octet C={0,sizeof(c),c};
    char ca[80];
    octet CA={0,sizeof(ca),ca};
    char owner[80];
    octet OWNER={0,sizeof(owner),owner};
    char b[3072];  // maximum size for CA certs in base64
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
    char b[2000];
    printf( "-----BEGIN CERTIFICATE----- ");
    printf("\n");
    OCT_tobase64(b,CERT);
    printf("%s\n",b);
    printf("-----END CERTIFICATE----- ");
    printf("\n");
}

pktype GET_PUBLIC_KEY_FROM_SIGNED_CERT(octet *SCERT,octet *PUBLIC_KEY)
{
    char cert[2048];
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

    printf("Public key= "); OCT_output(PUBKEY);
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

#define CHOICE USE_NIST256

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
        char r[66];
        octet R={0,sizeof(r),r};
        char s[66];
        octet S={0,sizeof(s),s};
        int siglen=SIG->len/2;
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

        printf("Checking ECC Signature on Cert\n");
        int res = NIST256::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
        if (res != 0)
            printf("ECP Public Key is invalid!\n");
        else printf("ECP Public Key is Valid\n");

        if (NIST256::ECP_VP_DSA(sha, PUBKEY, CERT, &R, &S) != 0)
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
        char p1[RFS_RSA2048];
        octet P1={0,sizeof(p1),p1};
        char p2[RFS_RSA2048];
        octet P2={0,sizeof(p2),p2};
        printf("SIG= \n");
        OCT_output(SIG);
        printf("\n");
        printf("RSA PUBLIC KEY= \n");
        OCT_output(PUBKEY);

        RSA2048::rsa_public_key PK;
        printf("Checking CA's RSA Signature on Cert\n");
        PK.e = 65537; // assuming this!
        RSA2048::RSA_fromOctet(PK.n, PUBKEY);

        core::PKCS15(sha, CERT, &P1);
        RSA2048::RSA_ENCRYPT(&PK, SIG, &P2);

        if (OCT_comp(&P1, &P2))
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
    char sig[512];  // signature on certificate
    octet SIG={0,sizeof(sig),sig};
    char scert[2048]; // signed certificate
    octet SCERT={0,sizeof(scert),scert};
    char cert[2048];  // certificate
    octet CERT={0,sizeof(cert),cert};
    char cakey[512];  // Public Key from Cert
    octet CAKEY = {0, sizeof(cakey), cakey};
    char issuer[80];  
    octet ISSUER={0,sizeof(issuer),issuer};
    char subject[80];
    octet SUBJECT={0,sizeof(subject),subject};

    int len=parseInt24(CERTCHAIN,ptr); // get length of first (server) certificate
    parseOctet(&SCERT,len,CERTCHAIN,ptr); 

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions

    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,PUBKEY);
    st=GET_CERT_DETAILS(&SCERT,&CERT,&SIG,&ISSUER,&SUBJECT);

    SHOW_CERT_DETAILS((char *)"Server certificate",PUBKEY,ca,&SIG,st,&ISSUER,&SUBJECT);

    printf("cert.len= %d, ptr= %d\n",CERTCHAIN->len,ptr);
    len=parseInt24(CERTCHAIN,ptr); // get length of next certificate
    parseOctet(&SCERT,len,CERTCHAIN,ptr); 

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions

    ca=GET_PUBLIC_KEY_FROM_SIGNED_CERT(&SCERT,&CAKEY);

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
        printf("type= %d, hash= %d, curve/len= %d\n",stn.type,stn.hash,stn.curve); 
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
