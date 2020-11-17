// TLS Server Certchain Code
#include "tls_cert_chain.h"
#include "tls_parse_octet.h"

// Baltimore root certificate
char baltimore[] = "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJRTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYDVQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoXDTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9yZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVyVHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKrmD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjrIZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeKmpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSuXmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZydc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/yejl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT929hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3WgxjkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhzksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLSR9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp";

static void print_out(char *des, octet *c, int index, int len)
{
    int i;
    printf("%s [", des);
    for (i = 0; i < len; i++)
        printf("%c", c->val[index + i]);
    printf("]\n");
}

static void print_date(char *des, octet *c, int index)
{
    int i = index;
    printf("%s [", des);
    if (i == 0) printf("]\n");
    else printf("20%c%c-%c%c-%c%c %c%c:%c%c:%c%c]\n", c->val[i], c->val[i + 1], c->val[i + 2], c->val[i + 3], c->val[i + 4], c->val[i + 5], c->val[i + 6], c->val[i + 7], c->val[i + 8], c->val[i + 9], c->val[i + 10], c->val[i + 11]);
}

// given root issuer and public key type of signature, search through root CAs and return root public key
bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY)
{
    char sc[8192];
    octet SC={0,sizeof(sc),sc};
    char c[8192];
    octet C={0,sizeof(c),c};
    char ca[50];
    octet CA={0,sizeof(ca),ca};
    char owner[50];
    octet OWNER={0,sizeof(owner),owner};
    char b[8192];
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

void GET_CERT_DETAILS(octet *CERTIFICATE,octet *CERT,octet *PUBKEY,pktype *pk,octet *SIG,pktype *sg,octet *ISSUER,octet *SUBJECT)
{
    int c,ic,len;

    *sg = X509_extract_cert_sig(CERTIFICATE, SIG);
    X509_extract_cert(CERTIFICATE, CERT);
    *pk=X509_extract_public_key(CERT, PUBKEY);

    ic = X509_find_issuer(CERT);
    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
    OCT_clear(ISSUER);
    OCT_jbytes(ISSUER,&CERT->val[c],len);

    ic = X509_find_subject(CERT);
    c = X509_find_entity_property(CERT, &X509_MN, ic, &len);
    OCT_clear(SUBJECT);
    OCT_jbytes(SUBJECT,&CERT->val[c],len);
}

void SHOW_CERT_DETAILS(octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT)
{
    printf("\nImportant Certificate Details\n");
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
        RSA_ENCRYPT(&PK, SIG, &P2);

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

//extract server cert and public key, and check validity of certificate chain
bool CHECK_CERT_CHAIN(octet *CERTCHAIN,octet *CERT,octet *PUBKEY)
{
    int c,ptr=0;
    bool self_signed;
    pktype st,ca,stn;
    char sig[512];
    octet SIG={0,sizeof(sig),sig};
    char scert[2000];
    octet SCERT={0,sizeof(scert),scert};
    char r[64];
    octet R={0,sizeof(r),r};
    char s[64];
    octet S={0,sizeof(s),s};
    char issuer[50];
    octet ISSUER={0,sizeof(issuer),issuer};
    char subject[50];
    octet SUBJECT={0,sizeof(subject),subject};

    int len=parseInt24(CERTCHAIN,ptr); // get length of first (server) certificate
    parseOctet(&SCERT,len,CERTCHAIN,ptr); 

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions

    GET_CERT_DETAILS(&SCERT,CERT,PUBKEY,&ca,&SIG,&st,&ISSUER,&SUBJECT);
    SHOW_CERT_DETAILS(PUBKEY,ca,&SIG,st,&ISSUER,&SUBJECT);

    char ncert[2000];
    octet NCERT={0,sizeof(ncert),ncert};
    char icert[2000];
    octet ICERT={0,sizeof(icert),icert};
    char cakey[500];
    octet CAKEY = {0, sizeof(cakey), cakey};
    char nsig[512];
    octet NSIG={0,sizeof(nsig),nsig};
    printf("cert.len= %d, ptr= %d\n",CERTCHAIN->len,ptr);
    len=parseInt24(CERTCHAIN,ptr); // get length of next certificate
    parseOctet(&NCERT,len,CERTCHAIN,ptr); 

    len=parseInt16(CERTCHAIN,ptr);
    ptr+=len;   // skip certificate extensions

    GET_CERT_DETAILS(&NCERT,&ICERT,&CAKEY,&ca,&NSIG,&stn,&ISSUER,&SUBJECT);
    SHOW_CERT_DETAILS(&CAKEY,ca,&NSIG,stn,&ISSUER,&SUBJECT);

    if (CHECK_CERT_SIG(st,CERT,&SIG,&CAKEY)) {
        printf("Intermediate Certificate Chain sig is OK\n");
    } else {
        printf("Intermediate Certificate Chain sig is NOT OK\n");
        return false;
    }

    char rootkey[500];
    octet ROOTKEY = {0, sizeof(rootkey), rootkey};

    if (FIND_ROOT_CA(&ISSUER,stn,&ROOTKEY)) {
        printf("\nPublic Key= "); OCT_output(&ROOTKEY);
        printf("type= %d, hash= %d, curve/len= %d\n",stn.type,stn.hash,stn.curve); 
    } else {
        printf("Root CA not found\n");
        return false;
    }

    if (CHECK_CERT_SIG(stn,&ICERT,&NSIG,&ROOTKEY)) {
        printf("Root Certificate sig is OK!!!!\n");
    } else {
        printf("Root Certificate sig is NOT OK\n");
        return false;
    }

    return true;
}
