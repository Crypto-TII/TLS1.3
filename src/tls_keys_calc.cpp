
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

void init_crypto_context(crypto *C)
{
    C->K={0,TLS_MAX_KEY,C->k};
    C->IV={0,12,C->iv};
    C->record=0;
}

void create_crypto_context(crypto *C,octet *K,octet *IV)
{ // initialise crypto structure
    OCT_copy(&(C->K),K);
    OCT_copy(&(C->IV),IV);
    C->record=0;
}

void increment_crypto_context(crypto *C)
{ //  increment record, and update IV
    unsigned char b[4];  
    b[3] = (unsigned char)(C->record);
    b[2] = (unsigned char)(C->record >> 8);
    b[1] = (unsigned char)(C->record >> 16);
    b[0] = (unsigned char)(C->record >> 24);
    for (int i=0;i<4;i++)
        C->IV.val[8+i]^=b[i];  // revert to original IV
    C->record++;
    b[3] = (unsigned char)(C->record);
    b[2] = (unsigned char)(C->record >> 8);
    b[1] = (unsigned char)(C->record >> 16);
    b[0] = (unsigned char)(C->record >> 24);
    for (int i=0;i<4;i++)
        C->IV.val[8+i]^=b[i];  // advance to new IV
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
unsign32 UPDATE_KEYS(crypto *context,octet *TS)
{
    int sha,key;
    char info[16];
    octet INFO = {0,sizeof(info),info};
    char nts[TLS_MAX_HASH];
    octet NTS={0,sizeof(nts),nts};

// find cipher suite
    sha=TS->len;
    key=context->K.len;

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"traffic upd");
    HKDF_Expand_Label(MC_SHA2,sha,&NTS,sha,TS,&INFO,NULL);

    OCT_copy(TS,&NTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->K),key,TS,&INFO,NULL);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->IV),12,TS,&INFO,NULL);
// reset record number
    context->record=0;
    return 0;
}

// get Key and IV from Traffic secret
void GET_KEY_AND_IV(int cipher_suite,octet *TS,crypto *context)
{
    int sha,key;
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
    char info[16];
    octet INFO = {0,sizeof(info),info};

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->K),key,TS,&INFO,NULL);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->IV),12,TS,&INFO,NULL);

    context->record=0;
}

// recover PSK from Resumption Master Secret
void RECOVER_PSK(int sha,octet *RMS,octet *NONCE,octet *PSK)
{
    char info[16];
    octet INFO = {0,sizeof(info),info};

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"resumption");
    HKDF_Expand_Label(MC_SHA2,sha,PSK,sha,RMS, &INFO, NONCE);
}

// Key Schedule code

// Get Early Secret and optional Binder Key (either External or Resumption)
void GET_EARLY_SECRET(int sha,octet *PSK,octet *ES,octet *BKE,octet *BKR)
{
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};    // Empty Hash
    char zk[TLS_MAX_HASH];              
    octet ZK = {0,sizeof(zk),zk};       // Zero Key
    char info[16];
    octet INFO = {0,sizeof(info),info};
    char ps[TLS_MAX_HASH];
    octet PS={0,sizeof(ps),ps};

    OCT_jbyte(&ZK,0,sha);  // Zero key

    if (PSK==NULL)
        OCT_copy(&PS,&ZK);
    else
        OCT_copy(&PS,PSK);

    SPhash(MC_SHA2,sha,&EMH,NULL);  // hash of ""

    HKDF_Extract(MC_SHA2,sha,ES,&ZK,&PS);  // hash function, ES is output, ZK is salt and PS is IKM

    if (BKE!=NULL)
    {  // External Binder Key
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"ext binder");
        HKDF_Expand_Label(MC_SHA2,sha,BKE,sha,ES,&INFO,&EMH);
    }
    if (BKR!=NULL)
    { // Resumption Binder Key
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"res binder");
        HKDF_Expand_Label(MC_SHA2,sha,BKR,sha,ES,&INFO,&EMH);
    }
}

// Get Later Secrets (Client Early Traffic Secret and Early Exporter Master Secret) - requires partial transcript hash H
void GET_LATER_SECRETS(int sha,octet *ES,octet *H,octet *CETS,octet *EEMS)
{
    char info[16];
    octet INFO = {0,sizeof(info),info};

    if (CETS!=NULL)
    {
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"c e traffic");
        HKDF_Expand_Label(MC_SHA2,sha,CETS,sha,ES,&INFO,H);
    }
    if (EEMS!=NULL)
    {
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"e exp master");
        HKDF_Expand_Label(MC_SHA2,sha,EEMS,sha,ES,&INFO,H);
    }
}

void GET_HANDSHAKE_SECRETS(int sha,octet *SS,octet *ES,octet *H,octet *HS,octet *CHTS,octet *SHTS)
{
    char ds[TLS_MAX_HASH];
    octet DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octet INFO = {0,sizeof(info),info};

    SPhash(MC_SHA2,sha,&EMH,NULL);  // hash of ""

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,ES,&INFO,&EMH);

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
}

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
void GET_APPLICATION_SECRETS(int sha,octet *HS,octet *SFH,octet *CFH,octet *CTS,octet *STS,octet *EMS,octet *RMS)
{
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

    OCT_jbyte(&ZK,0,sha);
    SPhash(MC_SHA2,sha,&EMH,NULL);  // 

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,HS,&INFO,&EMH);   // Use handshake secret from above
//    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,&MS,&DS,&ZK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CTS,sha,&MS,&INFO,SFH);

    printf("Client application traffic secret= ");OCT_output(CTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,STS,sha,&MS,&INFO,SFH);

    printf("Server application traffic secret= ");OCT_output(STS);

    if (EMS!=NULL)
    {
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"exp master");
        HKDF_Expand_Label(MC_SHA2,sha,EMS,sha,&MS,&INFO,SFH);
    }
    if (RMS!=NULL)
    {
        OCT_clear(&INFO);
        OCT_jstring(&INFO,(char *)"res master");
        HKDF_Expand_Label(MC_SHA2,sha,RMS,sha,&MS,&INFO,CFH);
    }
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
