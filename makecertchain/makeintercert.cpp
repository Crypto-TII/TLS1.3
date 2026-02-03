// Create an intermediate certificate and secret key
// An intermediate certificate is signed by the root certificate authority
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "tls_octads.h"
#include "tls_sal.h"
#include "tls_x509.h"

#define NIST256_PK 1
#define NIST384_PK 2
#define RSA_PK 3
#define ED25519_PK 7
#define ED448_PK 8
#define MLDSA65_PK 10
#define NIST256_MLDSA44_PK 11  // Hybrid

#ifdef SQISIGN_TEST
#define SQISIGN3_PK 12
#define ED448_SQISIGN3_PK 13
#endif

#define ECCSHA256_SIG 1
#define ECCSHA384_SIG 2
#define RSASHA256_SIG 4
#define RSASHA384_SIG 5
#define RSASHA512_SIG 6
#define ED25519_SIG 7
#define ED448_SIG 8
#define MLDSA65_SIG 10
#define ECC256SHA384_MLDSA44_SIG 11  // Hybrid

#ifdef SQISIGN_TEST
#define SQISIGN3_SIG 12
#define ED448_SQISIGN3_SIG 13
#endif

// BEGIN USER EDITABLE AREA *******************
#define DAYS 365
#define ISSUER_NAME "TiigerTLS root CA"
#define ISSUER_ORG "Tii Trust Services"
#define ISSUER_UNIT ""
#define ISSUER_COUNTRY "AE"
#define SUBJECT_NAME "TiigerTLS intermediate CA"
#define SUBJECT_ORG "Tii Trust Services"
#define SUBJECT_UNIT ""
#define SUBJECT_COUNTRY "AE"
#define PKTYPE RSA_PK // Intermediate cert public key type
#define SIGTYPE RSASHA256_SIG // Root CA signature

#if SIGTYPE==RSASHA256_SIG || SIGTYPE==RSASHA384_SIG || SIGTYPE==RSASHA512_SIG
#define RSA_IS_KEYLEN (2048/8)  // RSA only - issuer key length - use either 2048 or 4096
#endif
#if PKTYPE==RSA_PK
#define RSA_SB_KEYLEN (2048/8)  // RSA only - subject key length - use either 2048 or 4096
#endif

// END USER EDITABLE AREA *********************

// ASN.1 tags
#define ANY 0x00
#define SEQ 0x30
#define OID 0x06
#define INT 0x02
#define NUL 0x05
#define ZER 0x00
#define UTF 0x0C
#define UTC 0x17
#define GTM 0x18
#define LOG 0x01
#define BIT 0x03
#define OCT 0x04
#define STR 0x13
#define SET 0x31
#define IA5 0x16
#define EXT 0xA3
#define DNS 0x82
#define VRS 0xA0

// For OIDS see https://misc.daniel-marschall.de/asn.1/oid-converter/online.php
#if PKTYPE==NIST256_PK
static unsigned char pk_oid[10]= {OID,0x08,0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
#define SB_SK_SIZE 32 // secret key size
#define PK_SIZE 65    // public key size
#define PK_TYPE ECDSA_KP // key pair method
#endif
#if PKTYPE==NIST384_PK
static unsigned char pk_oid[7]= {OID,0x05,0x2B, 0x81, 0x04, 0x00, 0x22};
#define SB_SK_SIZE 48
#define PK_SIZE 97
#define PK_TYPE ECDSA_KP
#endif

#if PKTYPE==RSA_PK
static unsigned char pk_oid[11] = {OID,0x09,0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
#define SB_SK_SIZE (RSA_SB_KEYLEN/2)*5
#define PK_SIZE RSA_SB_KEYLEN
#define PK_TYPE RSA_KP
#endif
#if PKTYPE==ED25519_PK
static unsigned char pk_oid[5] = {OID,0x03,0x2B, 0x65, 0x70};  
#define SB_SK_SIZE 32
#define PK_SIZE 32
#define PK_TYPE EDDSA_KP
#endif
#if PKTYPE==ED448_PK
static unsigned char pk_oid[5] = {OID,0x03,0x2B, 0x65, 0x71};  
#define SB_SK_SIZE 57
#define PK_SIZE 57
#define PK_TYPE EDDSA_KP
#endif
#if PKTYPE==MLDSA65_PK
static unsigned char pk_oid[11] = {OID,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12};
#define SB_SK_SIZE 4032
#define PK_SIZE 1952
#define PK_TYPE MLDSA_KP
#endif
#if PKTYPE==NIST256_MLDSA44_PK
static unsigned char pk_oid[7] = {OID,0x05,0x2B,0xCE,0x0F,0x07,0x05};
#define HYBRID_PK
#define SB_SK_SIZE_1 32
#define SB_SK_SIZE_2 2560
#define PK_SIZE_1 65
#define PK_SIZE_2 1312
#define PK_TYPE_1 ECDSA_KP 
#define PK_TYPE_2 MLDSA_KP
#endif

#ifdef SQISIGN_TEST

#if PKTYPE==SQISIGN3_PK
static unsigned char pk_oid[11] = {OID,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x17};
#define SB_SK_SIZE 529
#define PK_SIZE 97
#define PK_TYPE SQISIGN_KP
#endif

#if PKTYPE==ED448_SQISIGN3_PK
static unsigned char pk_oid[7] = {OID,0x05,0x2B,0xCE,0x0F,0x07,0x06};
#define HYBRID_PK
#define SB_SK_SIZE_1 57
#define SB_SK_SIZE_2 529
#define PK_SIZE_1 57
#define PK_SIZE_2 97
#define PK_TYPE_1 EDDSA_KP 
#define PK_TYPE_2 SQISIGN_KP
#endif

#endif

#if SIGTYPE==ECCSHA256_SIG
static unsigned char sig_oid[10] = {OID,0x08,0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
#define IS_PK_SIZE 65 // Issuer Public Key size
#define SK_SIZE 32   // secret key size
#define SIG_SIZE 64  // signature size
#define SIG_TYPE ECDSA_SECP256R1_SHA256 // signature algorithm
#endif
#if SIGTYPE==ECCSHA384_SIG
static unsigned char sig_oid[10] = {OID, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
#define IS_PK_SIZE 97
#define SK_SIZE 48
#define SIG_SIZE 96
#define SIG_TYPE ECDSA_SECP384R1_SHA384
#endif
#if SIGTYPE==RSASHA256_SIG
static unsigned char sig_oid[11] = {OID,0x09,0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
#define IS_PK_SIZE RSA_IS_KEYLEN
#define SK_SIZE (RSA_IS_KEYLEN/2)*5
#define SIG_SIZE RSA_IS_KEYLEN
#define SIG_TYPE RSA_PKCS1_SHA256
#endif
#if SIGTYPE==RSASHA384_SIG
static unsigned char sig_oid[11] = {OID,0x09,0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};
#define IS_PK_SIZE RSA_IS_KEYLEN
#define SK_SIZE (RSA_IS_KEYLEN/2)*5
#define SIG_SIZE RSA_IS_KEYLEN
#define SIG_TYPE RSA_PKCS1_SHA384
#endif
#if SIGTYPE==RSASHA512_SIG
static unsigned char sig_oid[11] = {OID,0x09,0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};
#define IS_PK_SIZE RSA_IS_KEYLEN
#define SK_SIZE (RSA_IS_KEYLEN/2)*5
#define SIG_SIZE RSA_IS_KEYLEN
#define SIG_TYPE RSA_PKCS1_SHA512
#endif
#if SIGTYPE==ED25519_SIG
static unsigned char sig_oid[5] = {OID,0x03,0x2B, 0x65, 0x70}; 
#define IS_PK_SIZE 32
#define SK_SIZE 32
#define SIG_SIZE 64
#define SIG_TYPE ED25519
#endif
#if SIGTYPE==ED448_SIG
static unsigned char sig_oid[5] = {OID,0x03,0x2B, 0x65, 0x71}; 
#define IS_PK_SIZE 57
#define SK_SIZE 57
#define SIG_SIZE 114
#define SIG_TYPE ED448
#endif
#if SIGTYPE==MLDSA65_SIG
static unsigned char sig_oid[11] = {OID,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x12};
#define IS_PK_SIZE 1952
#define SK_SIZE 4032
#define SIG_SIZE 3309
#define SIG_TYPE MLDSA65
#endif
#if SIGTYPE==ECC256SHA384_MLDSA44_SIG
static unsigned char sig_oid[7] = {OID,0x05,0x2B,0xCE,0x0F,0x07,0x05};
#define HYBRID_SIG
#define IS_PK_SIZE_1 65
#define IS_PK_SIZE_2 1312
#define SK_SIZE_1 32
#define SK_SIZE_2 2560
#define SIG_SIZE_1 64
#define SIG_SIZE_2 2420
#define SIG_TYPE_1 ECDSA_SECP256R1_SHA384
#define SIG_TYPE_2 MLDSA44
#endif

#ifdef SQISIGN_TEST

#if SIGTYPE==SQISIGN3_SIG
static unsigned char sig_oid[11] = {OID,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x03,0x17};
#define IS_PK_SIZE 97
#define SK_SIZE 529
#define SIG_SIZE 224
#define SIG_TYPE SQISIGN3
#endif

#if SIGTYPE==ED448_SQISIGN3_SIG
static unsigned char sig_oid[7] = {OID,0x05,0x2B,0xCE,0x0F,0x07,0x06};
#define HYBRID_SIG
#define IS_PK_SIZE_1 57
#define IS_PK_SIZE_2 97
#define SK_SIZE_1 57
#define SK_SIZE_2 529
#define SIG_SIZE_1 114
#define SIG_SIZE_2 224
#define SIG_TYPE_1 ED448
#define SIG_TYPE_2 SQISIGN3
#endif

#endif

static octad PK_OID = {sizeof(pk_oid), sizeof(pk_oid), (char *)pk_oid};
static octad SIG_OID = {sizeof(sig_oid), sizeof(sig_oid), (char *)sig_oid};

// Indicates elliptic curve cryptography
static unsigned char ec_oid[9]={OID,0x07,0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static octad EC_OID={sizeof(ec_oid),sizeof(ec_oid),(char *)ec_oid};

static unsigned char nill[2]={NUL,0x00};
static octad NILL={2,2,(char *)nill};        
static unsigned char zero[3]={INT,0x01,0x00};
static octad ZERO={3,3,(char *)zero};  
static unsigned char one[3]={INT,0x01,0x01};
static octad ONE={3,3,(char *)one};

// myName - 2.5.4.3 (aka common name)
static char mn[5]= {OID,0x03,0x55,0x04,0x03};
static octad X509_mn= {5,sizeof(mn),mn};

// countryName
static unsigned char cn[5] = {OID,0x03,0x55, 0x04, 0x06};
static octad X509_cn = {5, sizeof(cn), (char *)cn};

// stateName
static char sn[5]= {OID,0x03,0x55,0x04,0x08};
static octad X509_sn= {5,sizeof(sn),sn};

// localName
static char ln[5]= {OID,0x03,0x55,0x04,0x07};
static octad X509_ln= {5,sizeof(ln),ln};

// orgName
static unsigned char on[5] = {OID,0x03,0x55, 0x04, 0x0A};
static octad X509_on = {5, sizeof(on), (char *)on};

// unitName
static char un[5]= {OID,0x03,0x55,0x04,0x0B};
static octad X509_un= {5,sizeof(un),un};

// emailName
//static unsigned char en[11] = {OID,0x09,0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};
//static octad X509_en = {11, sizeof(en), (char *)en};

// Extensions
// Alt Name
static char an[5]={OID,0x03,0x55,0x1D,0x11};
static octad X509_an = {5, sizeof(an),an};

// basic constraints 2.5.29.19
static unsigned char bc_oid[5] = {OID,0x03,0x55, 0x1D, 0x13};
static octad BC_OID = {5,sizeof(bc_oid),(char *)bc_oid};

// 65537
static unsigned char e65537[5]={INT,0x03,0x01,0x00,0x01};
static octad E65537 = {5,sizeof(e65537),(char *)e65537};

static char *issuer_name=(char *)ISSUER_NAME;
static char *issuer_org=(char *)ISSUER_ORG;
static char *issuer_unit=(char *)ISSUER_UNIT;
static char *issuer_country=(char *)ISSUER_COUNTRY;
static char *subject_name=(char *)SUBJECT_NAME; 
static char *subject_org=(char *)SUBJECT_ORG;
static char *subject_unit=(char *)SUBJECT_UNIT;
static char *subject_country=(char *)SUBJECT_COUNTRY;


#ifdef HYBRID_PK
static char secret[SB_SK_SIZE_1];
static char secret2[SB_SK_SIZE_2];
static char publickey[PK_SIZE_1];
static char publickey2[PK_SIZE_2];
static octad SECRET={SB_SK_SIZE_1,sizeof(secret),(char *)secret};
static octad SECRET2={SB_SK_SIZE_2,sizeof(secret2),(char *)secret2};
static octad PUBLICKEY={PK_SIZE_1,sizeof(publickey),(char *)publickey};
static octad PUBLICKEY2={PK_SIZE_2,sizeof(publickey2),(char *)publickey2};
#else
static char secret[SB_SK_SIZE];
static octad SECRET={SB_SK_SIZE,sizeof(secret),(char *)secret};
static char publickey[PK_SIZE];
static octad PUBLICKEY={PK_SIZE,sizeof(publickey),(char *)publickey};
static octad SECRET2={0,0,NULL};
static octad PUBLICKEY2={0,0,NULL};
#endif

#ifdef HYBRID_SIG
static char signature[SIG_SIZE_1];
static char signature2[SIG_SIZE_2];
static octad SIGNATURE={SIG_SIZE_1,sizeof(signature),(char *)signature};
static octad SIGNATURE2={SIG_SIZE_2,sizeof(signature2),(char *)signature2};
static char rootsecretkey[SK_SIZE_1];
static octad ROOTSECRETKEY={SK_SIZE_1,sizeof(rootsecretkey),(char *)rootsecretkey};
static char rootsecretkey2[SK_SIZE_2];
static octad ROOTSECRETKEY2={SK_SIZE_2,sizeof(rootsecretkey2),(char *)rootsecretkey2};

static char rootpublickey[IS_PK_SIZE_1];
static octad ROOTPUBLICKEY={IS_PK_SIZE_1,sizeof(rootpublickey),(char *)rootpublickey};
static char rootpublickey2[IS_PK_SIZE_2];
static octad ROOTPUBLICKEY2={IS_PK_SIZE_2,sizeof(rootpublickey2),(char *)rootpublickey2};
#else
static char signature[SIG_SIZE];
static octad SIGNATURE={SIG_SIZE,sizeof(signature),(char *)signature};
static octad SIGNATURE2={0,0,NULL};
static char rootsecretkey[SK_SIZE];  
static octad ROOTSECRETKEY={SK_SIZE,sizeof(rootsecretkey),(char *)rootsecretkey};
static octad ROOTSECRETKEY2={0,0,NULL};

static char rootpublickey[IS_PK_SIZE];
static octad ROOTPUBLICKEY={IS_PK_SIZE,sizeof(rootpublickey),(char *)rootpublickey};
static octad ROOTPUBLICKEY2={0,0,NULL};
#endif

// Certificate will be valid from now to now+days
static void validity(int days,unsigned char *start,unsigned char* expiry)
{
    time_t now=time(NULL);
    struct tm t = *localtime(&now);
    int year=t.tm_year-100;
    int month=t.tm_mon + 1;
    int day=t.tm_mday;
    start[0]=0x30+(year/10); start[1]=0x30+(year%10); start[2]=0x30+(month/10); start[3]=0x30+(month%10); start[4]=0x30+(day/10); start[5]=0x30+(day%10);
    start[6]=start[7]=start[8]=start[9]=start[10]=start[11]=0x30; start[12]=0x5A;
    t.tm_mday+=days;
    mktime(&t);
    year=t.tm_year-100;
    month=t.tm_mon + 1;
    day=t.tm_mday;
    expiry[0]=0x30+(year/10); expiry[1]=0x30+(year%10); expiry[2]=0x30+(month/10); expiry[3]=0x30+(month%10); expiry[4]=0x30+(day/10); expiry[5]=0x30+(day%10);
    expiry[6]=expiry[7]=expiry[8]=expiry[9]=expiry[10]=expiry[11]=0x30; expiry[12]=0x5A;
}

// asn.1 tag followed by length
static int setolen(int tag, int len, octad *b)
{
    b->val[0]=tag;
    if (len<128)
    {
        b->val[1]=len;
        b->len=2;
        return b->len;
    }
    if (len<256)
    {
        b->val[1]=0x81;
        b->val[2]=len;
        b->len=3;
        return b->len;
    }
    b->val[1]=0x82;
    b->val[2]=len/256;
    b->val[3]=len%256;
    b->len=4;
    return b->len;
}

// asn.1 tag followed by length followed by data of lenth len
static void makeclause(int tag, int dlen, unsigned char *data, octad *b)
{
    int i,k,pad=0;
    int len=dlen;
    b->val[0]=tag;
    if (tag==BIT || (tag==INT && data[0]>127)) {pad=1; len++;}
    k=setolen(tag,len,b);
    if (pad)
    {
        b->val[k]=0x00;
        k++;
    }
    for (i=0;i<dlen;i++)
        b->val[k++]=data[i];
    
    b->len=k;
}

// prepend a byte
static void insertbyte(octad *INNER,unsigned char byte) {
    int i,ilen=INNER->len;
    for (i=ilen-1;i>=0;i--)
        INNER->val[i+1]=INNER->val[i];
    INNER->val[0]=byte;
    INNER->len+=1;
}

// wrap octad inside a tagged field
static void wrap(int tag,octad *INNER) {
    int i,len,ilen;
    unsigned char outer[5];
    octad OUTER={0,5,(char *)outer};
    if (tag==BIT || (tag==INT && INNER->val[0]>127)) insertbyte(INNER,0x00);
    ilen=INNER->len;
    setolen(tag,INNER->len,&OUTER);

    len=OUTER.len;
    for (i=ilen-1;i>=0;i--)
        INNER->val[i+len]=INNER->val[i];
    for (i=0;i<len;i++)
        INNER->val[i]=OUTER.val[i];
    INNER->len+=len;
}

// add validity field
static void add_validity(octad *TOTAL, unsigned char *start_date,unsigned char *expiry_date)
{
    unsigned char validity[50];
    octad VALIDITY={0,50,(char *)validity};
    unsigned char begintime[20];
    octad BEGINTIME={0,20,(char *)begintime};
    unsigned char endtime[20];
    octad ENDTIME={0,20,(char *)endtime};

    makeclause(UTC,13,start_date,&BEGINTIME);
    makeclause(UTC,13,expiry_date,&ENDTIME);

    setolen(SEQ,BEGINTIME.len+ENDTIME.len,&VALIDITY);
    OCT_append_octad(&VALIDITY,&BEGINTIME);
    OCT_append_octad(&VALIDITY,&ENDTIME);

    OCT_append_octad(TOTAL,&VALIDITY);

//    char buff[10000];
//    OCT_output_hex(&VALIDITY,10000,buff);

//    printf("validity= %s\n",buff);
}

static void add_publickey(octad *TOTAL,octad *PUBLIC_KEY,octad *PUBLIC_KEY2)
{
//    char buff[10000];
    unsigned char pk[10000];
    octad PK={0,10000,(char *)pk};
    unsigned char pkinfo[10000];
    octad PKINFO={0,10000,(char *)pkinfo};

// RSA
#if PKTYPE==RSA_PK
    OCT_append_octad(&PKINFO,&PK_OID);  // PK_OID = 06 09 ....
    wrap(SEQ,&PKINFO);

    makeclause(INT,PUBLIC_KEY->len,(unsigned char*)PUBLIC_KEY->val,&PK);
    OCT_append_octad(&PK,&E65537);
    wrap(SEQ,&PK);
    wrap(BIT,&PK);
    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif

// MLDSA or EDDSA
#if PKTYPE==MLDSA65_PK || PKTYPE==ED25519_PK || PKTYPE==ED448_PK
    OCT_append_octad(&PKINFO,&PK_OID);  // PK_OID = 06 09 ....
    wrap(SEQ,&PKINFO);

    makeclause(BIT,PUBLIC_KEY->len,(unsigned char*)PUBLIC_KEY->val,&PK);
    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif

#ifdef SQISIGN_TEST
#if PKTYPE==SQISIGN3_PK
    OCT_append_octad(&PKINFO,&PK_OID);  // PK_OID = 06 09 ....
    wrap(SEQ,&PKINFO);

    makeclause(BIT,PUBLIC_KEY->len,(unsigned char*)PUBLIC_KEY->val,&PK);
    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif
#endif

#if PKTYPE==NIST256_MLDSA44_PK
    OCT_append_octad(&PKINFO,&PK_OID);  // PK_OID = 06 09 ....
    wrap(SEQ,&PKINFO);

    OCT_append_octad(&PK,PUBLIC_KEY); OCT_append_octad(&PK,PUBLIC_KEY2);
    insertbyte(&PK,0x41); insertbyte(&PK,0x00); insertbyte(&PK,0x00); insertbyte(&PK,0x00); // 0x41=65 = length of EC public key    
    wrap(BIT,&PK);

    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif

#ifdef SQISIGN_TEST

#if PKTYPE==ED448_SQISIGN3_PK
    OCT_append_octad(&PKINFO,&PK_OID);  // PK_OID = 06 09 ....
    wrap(SEQ,&PKINFO);

    OCT_append_octad(&PK,PUBLIC_KEY); OCT_append_octad(&PK,PUBLIC_KEY2);
    insertbyte(&PK,0x39); insertbyte(&PK,0x00); insertbyte(&PK,0x00); insertbyte(&PK,0x00); // 0x41=65 = length of EC public key    
    wrap(BIT,&PK);

    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif

#endif

// ECDSA
#if PKTYPE==NIST256_PK || PKTYPE==NIST384_PK
    OCT_append_octad(&PKINFO,&EC_OID); OCT_append_octad(&PK,&PK_OID);
    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO); // SEQ LEN OID LEN OID LEN
    makeclause(BIT,PUBLIC_KEY->len,(unsigned char *)PUBLIC_KEY->val,&PK);
    OCT_append_octad(&PKINFO,&PK);
    wrap(SEQ,&PKINFO);
#endif

    OCT_append_octad(TOTAL,&PKINFO);

//    OCT_output_hex(&PKINFO,10000,buff);
//    printf("PK= %s\n",buff);
}


// add signature oid
static void add_signature(octad *TOTAL) 
{
    //char buff[10000];
    unsigned char signature[30];
    octad SIGNATURE={0,30,(char *)signature};

    OCT_append_octad(&SIGNATURE,&SIG_OID);
    OCT_append_octad(&SIGNATURE,&NILL);
    wrap(SEQ,&SIGNATURE);

    OCT_append_octad(TOTAL,&SIGNATURE);

    //OCT_output_hex(&SIGNATURE,10000,buff);
    //printf("SIG= %s\n",buff);
}

//300F 0603 551D13 0101FF 0405 3003 0101FF
// add a basic constraint extension
static void add_extension_bc(octad *EXTENSIONS)
{
//    char buff[1000];
    unsigned char bc[50];
    octad BC={0,50,(char *)bc};
    unsigned char en[10];
    octad EN={0,10,(char *)en};
    setolen(LOG,1,&EN); OCT_append_byte(&EN,0xff,1);
    OCT_append_octad(&BC,&BC_OID); OCT_append_octad(&BC,&EN);
    wrap(SEQ,&EN);
    wrap(OCT,&EN);
    OCT_append_octad(&BC,&EN);
    wrap(SEQ,&BC);

    OCT_append_octad(EXTENSIONS,&BC);

//    OCT_output_hex(&BC,1000,buff);
//    printf("bc= %s\n",buff);
}

// generate random serial number
static void add_serial_number(octad *TOTAL)
{
//    char buff[1000];
    unsigned char sn[20];
    octad SN={0,20,(char *)sn};
    setolen(INT,16,&SN);
    for (int i=0;i<16;i++)
    {
        if (i==0)
            OCT_append_byte(&SN,(char)rand()&0x7F,1);
        else
            OCT_append_byte(&SN,(char)rand(),1);   // serial number
    }
    OCT_append_octad(TOTAL,&SN);

//    OCT_output_hex(&SN,1000,buff);
//    printf("serial number= %s\n",buff);
}

static void add_version(octad *TOTAL) 
{
//    char buff[1000];
    unsigned char version[10];
    octad VERSION={0,10,(char *)version};
    setolen(INT,1,&VERSION); OCT_append_byte(&VERSION,0x02,1); 
    wrap(VRS,&VERSION);
    OCT_append_octad(TOTAL,&VERSION);

//    OCT_output_hex(&VERSION,1000,buff);
//    printf("version= %s\n",buff);
}

static void add_country(octad *ENTITY,char *country_name)
{
//    char buff[10000];
    unsigned char country[50];
    octad COUNTRY={0,50,(char *)country};
    static unsigned char astring[80];
    static octad ASTRING={0,80,(char *)astring};
    int len=strlen(country_name); if (len==0) return;
    OCT_append_octad(&COUNTRY,&X509_cn);
    makeclause(UTF,len,(unsigned char *)country_name,&ASTRING);
    OCT_append_octad(&COUNTRY,&ASTRING);
    wrap(SEQ,&COUNTRY);
    wrap(SET,&COUNTRY);
    OCT_append_octad(ENTITY,&COUNTRY);

//    OCT_output_hex(&COUNTRY,10000,buff);
//    printf("country= %s\n",buff);
}

static void add_common(octad *ENTITY,char *common_name)
{
//    char buff[10000];
    unsigned char name[50];
    octad NAME={0,50,(char *)name};
    static unsigned char astring[80];
    static octad ASTRING={0,80,(char *)astring};
    int len=strlen(common_name); if (len==0) return;
    OCT_append_octad(&NAME,&X509_mn);
    makeclause(UTF,len,(unsigned char *)common_name,&ASTRING);
    OCT_append_octad(&NAME,&ASTRING);
    wrap(SEQ,&NAME);
    wrap(SET,&NAME);
    OCT_append_octad(ENTITY,&NAME);

//    OCT_output_hex(&NAME,10000,buff);
//    printf("common= %s\n",buff);
}

static void add_organisation(octad *ENTITY,char *org_name)
{
//    char buff[10000];
    unsigned char name[50];
    octad NAME={0,50,(char *)name};
    static unsigned char astring[80];
    static octad ASTRING={0,80,(char *)astring};
    int len=strlen(org_name);  if (len==0) return;
    OCT_append_octad(&NAME,&X509_on);
    makeclause(UTF,len,(unsigned char *)org_name,&ASTRING);
    OCT_append_octad(&NAME,&ASTRING);
    wrap(SEQ,&NAME);
    wrap(SET,&NAME);
    OCT_append_octad(ENTITY,&NAME);

//    OCT_output_hex(&NAME,10000,buff);
//    printf("organisation= %s\n",buff);
}

static void add_unit(octad *ENTITY,char *unit_name)
{
//    char buff[10000];
    unsigned char name[50];
    octad NAME={0,50,(char *)name};
    static unsigned char astring[80];
    static octad ASTRING={0,80,(char *)astring};
    int len=strlen(unit_name);  if (len==0) return;
    OCT_append_octad(&NAME,&X509_un);
    makeclause(UTF,len,(unsigned char *)unit_name,&ASTRING);
    OCT_append_octad(&NAME,&ASTRING);
    wrap(SEQ,&NAME);
    wrap(SET,&NAME);
    OCT_append_octad(ENTITY,&NAME);

//    OCT_output_hex(&NAME,10000,buff);
//    printf("organisation= %s\n",buff);
}

// append digital signature to certificate
static void add_cert_signature(octad *CERT,octad *SIGNATURE,octad *SIGNATURE2)
{
//    char buff[10000];
    unsigned char certsig[20000];
    octad CERTSIG={0,20000,(char *)certsig};

#if SIGTYPE==ECC256SHA384_MLDSA44_SIG
    unsigned char second[100];
    octad SECOND={0,100,(char *)second};
    int half=SIG_SIZE_1/2;

    makeclause(INT,half,(unsigned char *)&SIGNATURE->val[0],&CERTSIG);
    makeclause(INT,half,(unsigned char *)&SIGNATURE->val[half],&SECOND);

    OCT_append_octad(&CERTSIG,&SECOND); 
    wrap(SEQ,&CERTSIG);
    wrap(ANY,&CERTSIG);
    insertbyte(&CERTSIG,0x00); insertbyte(&CERTSIG,0x00); // 0x48 = length of wrapped EC signature

    OCT_append_octad(&CERTSIG,SIGNATURE2);
    wrap(BIT,&CERTSIG);

    OCT_append_octad(CERT,&CERTSIG);
    return;

#endif

#ifdef SQISIGN_TEST
#if SIGTYPE==ED448_SQISIGN3_SIG

    OCT_append_octad(&CERTSIG,SIGNATURE);
    OCT_append_octad(&CERTSIG,SIGNATURE2);
    wrap(BIT,&CERTSIG);
    OCT_append_octad(CERT,&CERTSIG);
    return;

#endif
#endif

#if SIGTYPE==ECCSHA256_SIG || SIGTYPE==ECCSHA384_SIG
    unsigned char second[100];
    octad SECOND={0,100,(char *)second};
    int half=(SIGNATURE->len)/2;

    makeclause(INT,half,(unsigned char *)&SIGNATURE->val[0],&CERTSIG);
    makeclause(INT,half,(unsigned char *)&SIGNATURE->val[half],&SECOND);

    OCT_append_octad(&CERTSIG,&SECOND);
    wrap(SEQ,&CERTSIG);
    wrap(BIT,&CERTSIG);
#else
    makeclause(BIT,SIGNATURE->len,(unsigned char *)SIGNATURE->val,&CERTSIG); 
#endif
    OCT_append_octad(CERT,&CERTSIG);

//    OCT_output_hex(&CERTSIG,10000,buff);
//    printf("CERTSIG= %s\n",buff);
}

// convert raw private key to X.509 format
void create_private(octad *PRIVATE,octad *RAWPRIVATE,octad *RAWPRIVATE2) {
    int i,off,extra;
    unsigned char anoid[30];
    octad ANOID={0,30,(char *)anoid};
    unsigned char numbers[5000];
    octad NUMBERS={0,5000,(char *)numbers};
    unsigned char param[300];
    octad PARAM={0,300,(char *)param};    
#if PKTYPE==NIST256_PK || PKTYPE==NIST384_PK
        OCT_append_octad(&ANOID,&EC_OID); OCT_append_octad(&ANOID,&PK_OID);
        wrap(SEQ,&ANOID);
        makeclause(OCT,RAWPRIVATE->len,(unsigned char *)RAWPRIVATE->val,&PARAM);
        OCT_append_octad(&NUMBERS,&ONE); OCT_append_octad(&NUMBERS,&PARAM);
        wrap(SEQ,&NUMBERS);
        wrap(OCT,&NUMBERS);
        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&NUMBERS);
        wrap(SEQ,PRIVATE);
#endif
#if PKTYPE==ED25519_PK || PKTYPE==ED448_PK
        OCT_append_octad(&ANOID,&PK_OID);
        wrap(SEQ,&ANOID);
        OCT_append_octad(&NUMBERS,RAWPRIVATE);
        wrap(OCT,&NUMBERS);
        wrap(OCT,&NUMBERS);
        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&NUMBERS);
        wrap(SEQ,PRIVATE);
#endif
#if PKTYPE==MLDSA65_PK
        unsigned char pk[5000];
        octad PK={0,5000,(char *)pk};
        OCT_append_octad(&ANOID,&PK_OID);
        wrap(SEQ,&ANOID);
        setolen(OCT,32,&PK); OCT_append_byte(&PK,0x00,32);  // 32 byte seed for private key (not used)
        makeclause(OCT,RAWPRIVATE->len,(unsigned char *)RAWPRIVATE->val,&NUMBERS);
        OCT_append_octad(&PK,&NUMBERS);
        wrap(SEQ,&PK);
        wrap(OCT,&PK);
        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&PK);
        wrap(SEQ,PRIVATE);
#endif

#ifdef SQISIGN_TEST
#if PKTYPE==SQISIGN3_PK
        unsigned char pk[5000];
        octad PK={0,5000,(char *)pk};
        OCT_append_octad(&ANOID,&PK_OID);
        wrap(SEQ,&ANOID);
        makeclause(OCT,RAWPRIVATE->len,(unsigned char *)RAWPRIVATE->val,&NUMBERS);
        OCT_append_octad(&PK,&NUMBERS);
        wrap(SEQ,&PK);
        wrap(OCT,&PK);
        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&PK);
        wrap(SEQ,PRIVATE);
#endif
#endif

#ifdef HYBRID_PK
        unsigned char pk[5000];
        octad PK={0,5000,(char *)pk};
        unsigned char ecc[100];
        octad ECC={0,100,(char *)ecc};
        OCT_append_octad(&ANOID,&PK_OID);
        wrap(SEQ,&ANOID);
        OCT_append_octad(&PK,&ONE);
        makeclause(OCT,RAWPRIVATE->len,(unsigned char *)RAWPRIVATE->val,&ECC);
        OCT_append_octad(&PK,&ECC);
        wrap(SEQ,&PK);
        wrap(ANY,&PK);
        insertbyte(&PK,0x00); insertbyte(&PK,0x00);
        OCT_append_octad(&PK,RAWPRIVATE2);
        wrap(OCT,&PK);
        wrap(OCT,&PK);
        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&PK);
        wrap(SEQ,PRIVATE);
#endif

#if PKTYPE==RSA_PK
        int len=SB_SK_SIZE/5;
        OCT_append_octad(&ANOID,&PK_OID); OCT_append_octad(&ANOID,&NILL);
        OCT_append_octad(&NUMBERS,&ZERO);
        OCT_append_octad(&NUMBERS,&ZERO);
        OCT_append_octad(&NUMBERS,&E65537); 
        OCT_append_octad(&NUMBERS,&ZERO);
        for (int j=0;j<5;j++)
        {
            makeclause(INT,len,(unsigned char *)&RAWPRIVATE->val[j*len],&PARAM);
            OCT_append_octad(&NUMBERS,&PARAM);
        }        
        wrap(SEQ,&ANOID);
        wrap(SEQ,&NUMBERS);
        wrap(OCT,&NUMBERS);

        OCT_append_octad(PRIVATE,&ZERO);
        OCT_append_octad(PRIVATE,&ANOID);
        OCT_append_octad(PRIVATE,&NUMBERS);
        wrap(SEQ,PRIVATE);
#endif
}

int main() {
    char buff[20000],line[100];
    unsigned char start_date[13],expiry_date[13];
    int i,len,ptr;
    FILE *fp;
    unsigned char entity[500];
    octad ENTITY={0,500,(char *)entity};
    unsigned char cert[20000];
    octad CERT={0,20000,(char *)cert};
    unsigned char rawrootsecretkey[20000];
    octad RAWROOTSECRETKEY={0,20000,(char *)rawrootsecretkey};
    unsigned char rawrootpublickey[20000];
    octad RAWROOTPUBLICKEY={0,20000,(char *)rawrootpublickey};

    unsigned char extensions[500];
    octad EXTENSIONS={0,500,(char *)extensions};

    validity(DAYS,start_date,expiry_date);

    SAL_initLib();  // SHOULD IMPLEMENT TRUE RNG - edit tls_sal_m.xpp 
// generate public/private key pair!
#ifdef HYBRID_PK
    SAL_tlsKeypair(PK_TYPE_1,&SECRET,&PUBLICKEY);
    SAL_tlsKeypair(PK_TYPE_2,&SECRET2,&PUBLICKEY2);
#else
    SAL_tlsKeypair(PK_TYPE,&SECRET,&PUBLICKEY); // PKTYPE
#endif

// read in root signing key
    fp=fopen("root.key","rb");
    if (fgets(line,100,fp)==NULL) { // ignore first line
        printf("File error\n");
        return 0;
    }
    ptr=0;
    while(1) {
        if (fgets(line,100,fp)==NULL) {
            printf("File error\n");
            return 0;
        }            
        if (line[0]=='-') break;
        for (i=0;i<strlen(line)-1;i++)  // remove cr
            buff[ptr++]=line[i];
    }
    fclose(fp);

    OCT_from_base64(&CERT, buff);
    pktype ret=X509_extract_private_key(&CERT,&RAWROOTSECRETKEY);

// read in root public key
    fp=fopen("root.crt","rb");
    if (fgets(line,100,fp)==NULL) { // ignore first line
        printf("File error\n");
        return 0;
    }
    ptr=0;
    while(1) {
        if (fgets(line,100,fp)==NULL) {
            printf("File error\n");
            return 0;
        }            
        if (line[0]=='-') break;
        for (i=0;i<strlen(line)-1;i++)  // remove cr
            buff[ptr++]=line[i];
    }
    fclose(fp);

    OCT_from_base64(&CERT, buff);
    X509_extract_cert(&CERT,&CERT);
    pktype retp=X509_extract_public_key(&CERT,&RAWROOTPUBLICKEY);

    if (retp.type!=ret.type)
    {
        printf("Signature type does not match root public key\n");
        return 0;
    }

#ifdef HYBRID_SIG
        OCT_kill(&ROOTPUBLICKEY); OCT_kill(&ROOTPUBLICKEY2);
        OCT_append_bytes(&ROOTPUBLICKEY,RAWROOTPUBLICKEY.val,IS_PK_SIZE_1);
        OCT_append_bytes(&ROOTPUBLICKEY2,&RAWROOTPUBLICKEY.val[IS_PK_SIZE_1],IS_PK_SIZE_2);
#else
        OCT_kill(&ROOTPUBLICKEY);
        OCT_copy(&ROOTPUBLICKEY,&RAWROOTPUBLICKEY);        
#endif

    bool valid=false;
    switch (ret.type) {
        case X509_ECC :
            if (ret.curve==USE_NIST256)
            {
                #if SIGTYPE==ECCSHA256_SIG
                    valid=true;
                #endif
            }
            if (ret.curve==USE_NIST384)
            {
                #if SIGTYPE==ECCSHA384_SIG
                    valid=true;
                #endif
            }
            break;
        case X509_ECD :
            if (ret.curve==USE_ED25519)
            {
                #if SIGTYPE==ED25519_SIG
                    valid=true;
                #endif
            }
            if (ret.curve==USE_ED448)
            {
                #if SIGTYPE==ED448_SIG
                    valid=true;
                #endif
            }
            break;
        case X509_RSA :
            #if SIGTYPE==RSASHA256_SIG || SIGTYPE==RSASHA384_SIG || SIGTYPE==RSASHA512_SIG
                if ((SK_SIZE/5)*16==ret.curve) valid=true;
            #endif
            break;
        case X509_DLM :
            #if SIGTYPE==MLDSA65_SIG
                if (SK_SIZE*8==ret.curve) valid=true;
            #endif
            break;
        case X509_HY1:
            #if SIGTYPE==ECC256SHA384_MLDSA44_SIG
                if ((SK_SIZE_1+SK_SIZE_2)*8==ret.curve) valid=true; 
            #endif
            break;
#ifdef SQISIGN_TEST
        case X509_SQI :
            #if SIGTYPE==SQISIGN3_SIG
                if (SK_SIZE*8==ret.curve) valid=true;
            #endif
            break;
        case X509_HY2:
            #if SIGTYPE==ED448_SQISIGN3_SIG
                if ((SK_SIZE_1+SK_SIZE_2)*8==ret.curve) valid=true; 
            #endif
            break;
#endif

        default:
            break;
    }
    if (!valid)
    {
        printf("Secret key type or length do not match required signature\n");
        return 0;
    }

#ifdef HYBRID_SIG
    OCT_kill(&ROOTSECRETKEY); OCT_kill(&ROOTSECRETKEY2);
    OCT_append_bytes(&ROOTSECRETKEY,RAWROOTSECRETKEY.val,SK_SIZE_1);
    OCT_append_bytes(&ROOTSECRETKEY2,&RAWROOTSECRETKEY.val[SK_SIZE_1],SK_SIZE_2);
#else
    OCT_kill(&ROOTSECRETKEY);
    OCT_copy(&ROOTSECRETKEY,&RAWROOTSECRETKEY);
#endif

    srand(time(NULL));

// build certificate
    OCT_kill(&CERT);
    add_version(&CERT);
    add_serial_number(&CERT);
    add_signature(&CERT);

//build issuer
    add_country(&ENTITY,issuer_country);
    add_organisation(&ENTITY,issuer_org);
    add_unit(&ENTITY,issuer_unit);
    add_common(&ENTITY,issuer_name);
    wrap(SEQ,&ENTITY);
//add issuer
    OCT_append_octad(&CERT,&ENTITY);

// add validity period
    add_validity(&CERT,start_date,expiry_date);

// build subject
    OCT_kill(&ENTITY);
    add_country(&ENTITY,subject_country);
    add_organisation(&ENTITY,subject_org);
    add_unit(&ENTITY,subject_unit);
    add_common(&ENTITY,subject_name);
    wrap(SEQ,&ENTITY);
// add subject
    OCT_append_octad(&CERT,&ENTITY);
// add public key
    add_publickey(&CERT,&PUBLICKEY,&PUBLICKEY2);

// build extensions
    add_extension_bc(&EXTENSIONS);

    wrap(SEQ,&EXTENSIONS);
    wrap(EXT,&EXTENSIONS);

// add extensions
    OCT_append_octad(&CERT,&EXTENSIONS);

    wrap(SEQ,&CERT);  // ready to be signed

#ifdef HYBRID_SIG
    SAL_tlsSignature(SIG_TYPE_1,&ROOTSECRETKEY,&CERT,&SIGNATURE);
    SAL_tlsSignature(SIG_TYPE_2,&ROOTSECRETKEY2,&CERT,&SIGNATURE2);
#else
    SAL_tlsSignature(SIG_TYPE,&ROOTSECRETKEY,&CERT,&SIGNATURE);   // sign tbscert
#endif

#ifdef HYBRID_SIG
    if (!SAL_tlsSignatureVerify(SIG_TYPE_1,&CERT,&SIGNATURE,&ROOTPUBLICKEY) || !SAL_tlsSignatureVerify(SIG_TYPE_2,&CERT,&SIGNATURE2,&ROOTPUBLICKEY2))
#else
    if (!SAL_tlsSignatureVerify(SIG_TYPE,&CERT,&SIGNATURE,&ROOTPUBLICKEY))
#endif
    {
        printf("Signature by root failed to verify\n");
        return 0;
    }

// add signature oid (again)
    add_signature(&CERT);
// append signature
    add_cert_signature(&CERT,&SIGNATURE,&SIGNATURE2);

    wrap(SEQ,&CERT);

// output intermediate certificate and secret key to files
    OCT_output_base64(&CERT,20000,buff);
    fp=fopen("inter.crt","wt");
    int fin;
    fputs("-----BEGIN CERTIFICATE-----\n",fp);
    for (i=0;i<strlen(buff);i++)
    {
        fin=1;
        fputc(buff[i],fp);
        if ((i+1)%64==0) {fputc('\n',fp); fin=0;}
    }
    if (fin) fputc('\n',fp); 
    fputs("-----END CERTIFICATE-----\n",fp);
    fclose(fp);

    unsigned char private_key[5000];
    octad PRIVATE_KEY={0,5000,(char *)private_key};

    create_private(&PRIVATE_KEY,&SECRET,&SECRET2);

    OCT_output_base64(&PRIVATE_KEY,20000,buff);
    fp=fopen("inter.key","wt");
    fputs("-----BEGIN PRIVATE KEY-----\n",fp);
    for (i=0;i<strlen(buff);i++)
    {
        fin=1;
        fputc(buff[i],fp);
        if ((i+1)%64==0) {fputc('\n',fp); fin=0;}
    }
    if (fin) fputc('\n',fp);
    fputs("-----END PRIVATE KEY-----\n",fp);
    fclose(fp);

    //OCT_output_hex(&SECRET,20000,buff);
    //printf("SECRET= %s\n",buff);

    return 0;
}
