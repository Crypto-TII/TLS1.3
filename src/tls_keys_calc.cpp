//
// TLS1.3 crypto support functions
//
#include "tls_keys_calc.h"

// Add octet to transcript hash 
void running_hash(octet *O,unihash *h)
{
    for (int i=0;i<O->len;i++)
        Hash_Process(h,O->val[i]);
}

// Output transcript hash 
void transcript_hash(unihash *h,octet *O)
{
    Hash_Output(h,O->val); O->len=h->hlen; 
}

// special case handling for first clientHello after retry request
void running_syn_hash(octet *O,octet *E,unihash *h)
{
    int sha=h->hlen;
    unihash rhash;
    char hh[TLS_MAX_HASH];
    octet HH={0,sizeof(hh),hh};

    Hash_Init(sha,&rhash); 
 // RFC 8446 - "special synthetic message"
    running_hash(O,&rhash);
    running_hash(E,&rhash);
    transcript_hash(&rhash,&HH);
    
    Hash_Process(h,MESSAGE_HASH);
    Hash_Process(h,0); Hash_Process(h,0);
    Hash_Process(h,sha);   // fe 00 00 sha
    
    running_hash(&HH,h);
}

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

// Initialise crypto context (Key,IV, Record number)
void init_crypto_context(crypto *C)
{
    C->K.len = 0;
    C->K.max = TLS_MAX_KEY;
    C->K.val = C->k;

    C->IV.len = 0;
    C->IV.max = 12;
    C->IV.val = C->iv;

    C->record=0;
}

// Fill a crypto context with new key/IV
void create_crypto_context(crypto *C,octet *K,octet *IV)
{ 
    OCT_copy(&(C->K),K);
    OCT_copy(&(C->IV),IV);
    C->record=0;
}

//  increment record, and update IV
void increment_crypto_context(crypto *C)
{ 
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
void UPDATE_KEYS(crypto *context,octet *TS)
{
    int sha,key;
    char info[16];
    octet INFO = {0,sizeof(info),info};
    char nts[TLS_MAX_HASH];
    octet NTS={0,sizeof(nts),nts};

// find cipher suite
    sha=TS->len;        // depends on secret length
    key=context->K.len; // depends on key length

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
}

// get Key and IV from a Traffic secret
void GET_KEY_AND_IV(int cipher_suite,octet *TS,crypto *context)
{
    int sha,key;
    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=32;  // SHA256
        key=16;  // AES128
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=48; // SHA384
        key=32; // AES256
    }
    char info[8];
    octet INFO = {0,sizeof(info),info};

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->K),key,TS,&INFO,NULL);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,&(context->IV),12,TS,&INFO,NULL);

    context->record=0;
}

// recover Pre-Shared-Key from Resumption Master Secret
void RECOVER_PSK(int sha,octet *RMS,octet *NONCE,octet *PSK)
{
    char info[16];
    octet INFO = {0,sizeof(info),info};

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"resumption");
    HKDF_Expand_Label(MC_SHA2,sha,PSK,sha,RMS, &INFO, NONCE);
}

// Key Schedule code
// Get Early Secret ES and optional Binder Key (either External or Resumption)
void GET_EARLY_SECRET(int sha,octet *PSK,octet *ES,octet *BKE,octet *BKR)
{
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};  
    char zk[TLS_MAX_HASH];              
    octet ZK = {0,sizeof(zk),zk}; 
    char info[16];
    octet INFO = {0,sizeof(info),info};

    OCT_jbyte(&ZK,0,sha);  // Zero key

    if (PSK==NULL)
        OCT_copy(&EMH,&ZK);   // if no PSK available use ZK
    else
        OCT_copy(&EMH,PSK);

    HKDF_Extract(MC_SHA2,sha,ES,&ZK,&EMH);  // hash function, ES is output, ZK is salt and EMH is IKM

    SPhash(MC_SHA2,sha,&EMH,NULL);  // EMH = hash of ""

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

// Get Later Secrets (Client Early Traffic Secret CETS and Early Exporter Master Secret EEMS) - requires partial transcript hash H
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

// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
void GET_HANDSHAKE_SECRETS(int sha,octet *SS,octet *ES,octet *H,octet *HS,octet *CHTS,octet *SHTS)
{
    char ds[TLS_MAX_HASH];
    octet DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octet EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octet INFO = {0,sizeof(info),info};

    SPhash(MC_SHA2,sha,&EMH,NULL);      // hash of ""

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,ES,&INFO,&EMH);  

    HKDF_Extract(MC_SHA2,sha,HS,&DS,SS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CHTS,sha,HS,&INFO,H);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,SHTS,sha,HS,&INFO,H);
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

    OCT_jbyte(&ZK,0,sha);           // 00..00  
    SPhash(MC_SHA2,sha,&EMH,NULL);  // hash("")

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,HS,&INFO,&EMH);   // Use handshake secret from above

    HKDF_Extract(MC_SHA2,sha,&MS,&DS,&ZK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CTS,sha,&MS,&INFO,SFH);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,STS,sha,&MS,&INFO,SFH);

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
