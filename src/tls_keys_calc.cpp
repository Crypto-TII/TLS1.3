
// extract traffic, handshake and application keys from raw secrets
#include "tls_keys_calc.h"

// create expanded HKDF label LB from label and context
static void hkdfLabel(octet *LB,int length,octet *Label,octet *CTX)
{
    OCT_jint(LB,length,2);    // 2
    OCT_jbyte(LB,(char)(6+Label->len),1);  // 1
    OCT_jstring(LB,(char *)"tls13 ");   // 6
    OCT_joctet(LB,Label);  // Label->len
    if (CTX!=NULL)
    {
        OCT_jbyte(LB, (char)(CTX->len), 1); // 1
        OCT_joctet(LB,CTX);   // CTX->len
    } else {
        OCT_jbyte(LB,0,1);   // 1
    }
}

// HKDF extension for TLS1.3
static void HKDF_Expand_Label(int hash,int hlen,octet *OKM,int olen,octet *PRK,octet *Label,octet *CTX)
{
    char hl[TLS_MAX_HASH+24];
    octet HL={0,sizeof(hl),hl};
    hkdfLabel(&HL,olen,Label,CTX);
    HKDF_Expand(hash,hlen,OKM,olen,PRK,&HL);
}

// create verification data
void VERIFY_DATA(int sha,octet *CF,octet *CHTS,octet *H)
{
    char fk[TLS_MAX_HASH];
    octet FK = {0,sizeof(fk),fk};
    char info[10];
    octet INFO = {0,sizeof(info),info};
    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"finished");
    HKDF_Expand_Label(MC_SHA2,sha,&FK,sha,CHTS,&INFO,NULL); 

    HMAC(MC_SHA2,sha,CF,sha,&FK,H);
}

// check verification data
bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H)
{
    char vd[TLS_MAX_HASH];
    octet VD = {0,sizeof(vd),vd};
    VERIFY_DATA(sha,&VD,SHTS,H);
    return OCT_comp(SF,&VD);
}

// update Traffic secret and associated traffic key and IV
unsign32 UPDATE_KEYS(octet *K,octet *IV,octet *TS)
{
    int sha,key;
    char info[16];
    octet INFO = {0,sizeof(info),info};
    char nts[TLS_MAX_HASH];
    octet NTS={0,sizeof(nts),nts};

// find cipher suite
    sha=TS->len;
    key=K->len;

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"traffic upd");
    HKDF_Expand_Label(MC_SHA2,sha,&NTS,sha,TS,&INFO,NULL);

    OCT_copy(TS,&NTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,K,key,TS,&INFO,NULL);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,IV,12,TS,&INFO,NULL);
// reset record number
    return 0;
}

// Extract Client and Server Application keys and IVs from Transcript Hash, Handshake secret, 
void GET_APPLICATION_SECRETS(int cipher_suite,octet *CAK,octet *CAIV,octet *SAK,octet *SAIV,octet *CTS,octet *STS,octet *H,octet *HS)
{
    int sha,key;
    char ds[TLS_MAX_HASH];
    octet DS = {0,sizeof(ds),ds};
    char ms[TLS_MAX_HASH];
    octet MS = {0,sizeof(ms),ms};
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};
    char zk[TLS_MAX_HASH];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[16];
    octet INFO = {0,sizeof(info),info};

    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=32;
        key=16;
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=48;
        key=32;
    }

    OCT_jbyte(&ZK,0,sha);
    SPhash(MC_SHA2,sha,&EMH,NULL);  // 

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,HS,&INFO,&EMH);   // Use handshake secret from above
//    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,&MS,&DS,&ZK);
//    printf("Master Secret= ");OCT_output(&MS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CTS,sha,&MS,&INFO,H);

    printf("Client application traffic secret= ");OCT_output(CTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,STS,sha,&MS,&INFO,H);

    printf("Server application traffic secret= ");OCT_output(STS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CAK,key,CTS,&INFO,NULL);

    printf("Client application key= "); OCT_output(CAK);

    HKDF_Expand_Label(MC_SHA2,sha,SAK,key,STS,&INFO,NULL);

    printf("Server application key= "); OCT_output(SAK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CAIV,12,CTS,&INFO,NULL);

    printf("Client application IV= "); OCT_output(CAIV);

    HKDF_Expand_Label(MC_SHA2,sha,SAIV,12,STS,&INFO,NULL);

    printf("Server application IV= "); OCT_output(SAIV);
}

// Update IV, xor with record number, increment record number
// NIV - New IV
// OIV - Original IV
// See RFC8446 section 5.3
// OK recno should be 64-bit, but really that is excessive
unsign32 updateIV(octet *NIV,octet *OIV,unsign32 recno)
{
    int i;
    unsigned char b[4];  
    b[3] = (unsigned char)(recno);
    b[2] = (unsigned char)(recno >> 8);
    b[1] = (unsigned char)(recno >> 16);
    b[0] = (unsigned char)(recno >> 24);
    for (i=0;i<12;i++)
        NIV->val[i]=OIV->val[i];
    for (i=0;i<4;i++)
        NIV->val[8+i]^=b[i];
    NIV->len=12;
    recno++;  
    return recno;
}

// Extract Handshake secret, Client and Server Handshake keys and IVs, and Client and Server Handshake Traffic keys from Transcript Hash and Shared secret
void GET_HANDSHAKE_SECRETS(int cipher_suite,octet *HS,octet *CHK,octet *CHIV,octet *SHK,octet *SHIV, octet *CHTS,octet *SHTS,  octet *H,octet *SS)
{
    int sha,key;
    char es[TLS_MAX_HASH];
    octet ES = {0,sizeof(es),es};
    char ds[TLS_MAX_HASH];
    octet DS = {0,sizeof(ds),ds};
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};
    char zk[TLS_MAX_HASH];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[16];
    octet INFO = {0,sizeof(info),info};

    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=32;
        key=16;
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=48;
        key=32;
    }

    OCT_jbyte(&ZK,0,sha);
    SPhash(MC_SHA2,sha,&EMH,NULL);  // hash of ""

    HKDF_Extract(MC_SHA2,sha,&ES,&ZK,&ZK);  // hash function, ES is output, ZK is salt and IKM

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,&ES,&INFO,&EMH);

//    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,HS,&DS,SS);

    printf("Handshake Secret= ");OCT_output(HS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CHTS,sha,HS,&INFO,H);

    printf("Client handshake traffic secret= ");OCT_output(CHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,SHTS,sha,HS,&INFO,H);

    printf("Server handshake traffic secret= ");OCT_output(SHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CHK,key,CHTS,&INFO,NULL);

    printf("Client handshake key= "); OCT_output(CHK);

    HKDF_Expand_Label(MC_SHA2,sha,SHK,key,SHTS,&INFO,NULL);

    printf("Server handshake key= "); OCT_output(SHK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CHIV,12,CHTS,&INFO,NULL);

    printf("Client handshake IV= "); OCT_output(CHIV);

    HKDF_Expand_Label(MC_SHA2,sha,SHIV,12,SHTS,&INFO,NULL);

    printf("Server handshake IV= "); OCT_output(SHIV);
}

// generate a public/private key pair in an approved group for a key exchange
void GENERATE_KEY_PAIR(csprng *RNG,int group,octet *SK,octet *PK)
{
    int sklen=32;
    if (group==SECP384R1)
        sklen=48;
// Random secret key
    OCT_rand(SK,RNG,32);
    if (group==X25519)
    {
// RFC 7748
        OCT_reverse(SK);
        SK->val[32-1]&=248;  
        SK->val[0]&=127;
        SK->val[0]|=64;
        C25519::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
        OCT_reverse(PK);
    }
    if (group==SECP256R1)
    {
        NIST256::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
    }
    if (group==SECP384R1)
    {
        NIST384::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
    }
}

// generate shared secret SS from secret key SK and public hey PK
void GENERATE_SHARED_SECRET(int group,octet *SK,octet *PK,octet *SS)
{
    if (group==X25519)
    { // RFC 7748
        printf("X25519 Key Exchange\n");
        OCT_reverse(PK);
        C25519::ECP_SVDP_DH(SK, PK, SS,0);
        OCT_reverse(SS);
    }
    if (group==SECP256R1)
    {
        printf("SECP256R1 Key Exchange\n");
        NIST256::ECP_SVDP_DH(SK, PK, SS,0);
    }
    if (group==SECP384R1)
    {
        printf("SECP384R1 Key Exchange\n");
        NIST384::ECP_SVDP_DH(SK, PK, SS,0);
    }
}
