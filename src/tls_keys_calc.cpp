//
// TLS1.3 crypto support functions (hashing and AEAD encryption)
//
#include "tls_keys_calc.h"

// Add octad to transcript hash 
void running_hash(octad *O,unihash *h)
{
    for (int i=0;i<O->len;i++)
        Hash_Process(h,O->val[i]);
}

// Output transcript hash 
void transcript_hash(unihash *h,octad *O)
{
    Hash_Output(h,O->val); O->len=h->hlen; 
}

// special case handling for first clientHello after retry request
void running_syn_hash(octad *O,octad *E,unihash *h)
{
    int sha=h->hlen;
    unihash rhash;
    char hh[TLS_MAX_HASH];
    octad HH={0,sizeof(hh),hh};

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

// Initialise crypto context (Key,IV, Record number)
void init_crypto_context(crypto *C)
{
    C->K.len = 0;
    C->K.max = TLS_MAX_KEY;
    C->K.val = C->k;

    C->IV.len = 0;
    C->IV.max = 12;
    C->IV.val = C->iv;

    C->suite=TLS_AES_128_GCM_SHA256; // default
    C->record=0;
}

// Fill a crypto context with new key/IV
void create_crypto_context(crypto *C,octad *K,octad *IV)
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
void VERIFY_DATA(int sha,octad *CF,octad *CHTS,octad *H)
{
    char fk[TLS_MAX_HASH];
    octad FK = {0,sizeof(fk),fk};
    char info[10];
    octad INFO = {0,sizeof(info),info};
    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"finished");
    TLS_HKDF_Expand_Label(sha,&FK,sha,CHTS,&INFO,NULL); 
    TLS_HMAC(sha,CF,&FK,H);
}

// check verification data
bool IS_VERIFY_DATA(int sha,octad *SF,octad *SHTS,octad *H)
{
    char vd[TLS_MAX_HASH];
    octad VD = {0,sizeof(vd),vd};
    VERIFY_DATA(sha,&VD,SHTS,H);
    return OCT_compare(SF,&VD);
}

// update Traffic secret and associated traffic key and IV
void UPDATE_KEYS(crypto *context,octad *TS)
{
    int sha,key;
    char info[16];
    octad INFO = {0,sizeof(info),info};
    char nts[TLS_MAX_HASH];
    octad NTS={0,sizeof(nts),nts};

// find cipher suite
    sha=TS->len;        // depends on secret length
    key=context->K.len; // depends on key length

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"traffic upd");
    TLS_HKDF_Expand_Label(sha,&NTS,sha,TS,&INFO,NULL);

    OCT_copy(TS,&NTS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    TLS_HKDF_Expand_Label(sha,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    TLS_HKDF_Expand_Label(sha,&(context->IV),12,TS,&INFO,NULL);
// reset record number
    context->record=0;
}

// Build a crypto context from an input raw Secret and an agreed cipher_suite 
void GET_KEY_AND_IV(int cipher_suite,octad *TS,crypto *context)
{
    int sha,key;
    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=TLS_SHA256;  // SHA256
        key=TLS_AES_128;  // AES128
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=TLS_SHA384; // SHA384
        key=TLS_AES_256; // AES256
    }
    if (cipher_suite==TLS_CHACHA20_POLY1305_SHA256)
    {
        sha=TLS_SHA256; // SHA384
        key=TLS_CHA_256; // IETF CHACHA20
    }
    char info[8];
    octad INFO = {0,sizeof(info),info};

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    TLS_HKDF_Expand_Label(sha,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    TLS_HKDF_Expand_Label(sha,&(context->IV),12,TS,&INFO,NULL);

    context->suite=cipher_suite;
    context->record=0;
}

// recover Pre-Shared-Key from Resumption Master Secret
void RECOVER_PSK(int sha,octad *RMS,octad *NONCE,octad *PSK)
{
    char info[16];
    octad INFO = {0,sizeof(info),info};

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"resumption");
    TLS_HKDF_Expand_Label(sha,PSK,sha,RMS, &INFO, NONCE);
}

// Key Schedule code
// Get Early Secret ES and optional Binder Key (either External or Resumption)
void GET_EARLY_SECRET(int sha,octad *PSK,octad *ES,octad *BKE,octad *BKR)
{
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};  
    char zk[TLS_MAX_HASH];              
    octad ZK = {0,sizeof(zk),zk}; 
    char info[16];
    octad INFO = {0,sizeof(info),info};

    OCT_append_byte(&ZK,0,sha);  // Zero key

    if (PSK==NULL)
        OCT_copy(&EMH,&ZK);   // if no PSK available use ZK
    else
        OCT_copy(&EMH,PSK);

    TLS_HKDF_Extract(sha,ES,&ZK,&EMH);  // hash function, ES is output, ZK is salt and EMH is IKM

    TLS_HASH(sha,&EMH,NULL);  // EMH = hash of ""

    if (BKE!=NULL)
    {  // External Binder Key
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"ext binder");
        TLS_HKDF_Expand_Label(sha,BKE,sha,ES,&INFO,&EMH);
    }
    if (BKR!=NULL)
    { // Resumption Binder Key
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"res binder");
        TLS_HKDF_Expand_Label(sha,BKR,sha,ES,&INFO,&EMH);
    }
}

// Get Later Secrets (Client Early Traffic Secret CETS and Early Exporter Master Secret EEMS) - requires partial transcript hash H
void GET_LATER_SECRETS(int sha,octad *ES,octad *H,octad *CETS,octad *EEMS)
{
    char info[16];
    octad INFO = {0,sizeof(info),info};

    if (CETS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"c e traffic");
        TLS_HKDF_Expand_Label(sha,CETS,sha,ES,&INFO,H);
    }
    if (EEMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"e exp master");
        TLS_HKDF_Expand_Label(sha,EEMS,sha,ES,&INFO,H);
    }
}

// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
void GET_HANDSHAKE_SECRETS(int sha,octad *SS,octad *ES,octad *H,octad *HS,octad *CHTS,octad *SHTS)
{
    char ds[TLS_MAX_HASH];
    octad DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octad INFO = {0,sizeof(info),info};

    TLS_HASH(sha,&EMH,NULL);      // hash of ""
    //SPhash(MC_SHA2,sha,&EMH,NULL);      // hash of ""

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    TLS_HKDF_Expand_Label(sha,&DS,sha,ES,&INFO,&EMH);  

    TLS_HKDF_Extract(sha,HS,&DS,SS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c hs traffic");
    TLS_HKDF_Expand_Label(sha,CHTS,sha,HS,&INFO,H);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s hs traffic");
    TLS_HKDF_Expand_Label(sha,SHTS,sha,HS,&INFO,H);
}

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
void GET_APPLICATION_SECRETS(int sha,octad *HS,octad *SFH,octad *CFH,octad *CTS,octad *STS,octad *EMS,octad *RMS)
{
    char ds[TLS_MAX_HASH];
    octad DS = {0,sizeof(ds),ds};
    char ms[TLS_MAX_HASH];
    octad MS = {0,sizeof(ms),ms};
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};
    char zk[TLS_MAX_HASH];                    // Zero Key
    octad ZK = {0,sizeof(zk),zk};
    char info[16];
    octad INFO = {0,sizeof(info),info};

    OCT_append_byte(&ZK,0,sha);           // 00..00  
    TLS_HASH(sha,&EMH,NULL);  // hash("")
    //SPhash(MC_SHA2,sha,&EMH,NULL);  // hash("")

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    TLS_HKDF_Expand_Label(sha,&DS,sha,HS,&INFO,&EMH);   // Use handshake secret from above

    TLS_HKDF_Extract(sha,&MS,&DS,&ZK);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c ap traffic");
    TLS_HKDF_Expand_Label(sha,CTS,sha,&MS,&INFO,SFH);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s ap traffic");
    TLS_HKDF_Expand_Label(sha,STS,sha,&MS,&INFO,SFH);

    if (EMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"exp master");
        TLS_HKDF_Expand_Label(sha,EMS,sha,&MS,&INFO,SFH);
    }
    if (RMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"res master");
        TLS_HKDF_Expand_Label(sha,RMS,sha,&MS,&INFO,CFH);
    }
}
