//
// TLS1.3 crypto support functions (hashing, KDFs etc)
//

#include "tls_keys_calc.h"

// Add octad to transcript hash 
void runningHash(octad *O,unihash *h)
{
    for (int i=0;i<O->len;i++)
        SAL_hashProcess(h,O->val[i]);
}

// Output transcript hash 
void transcriptHash(unihash *h,octad *O)
{
    O->len=SAL_hashOutput(h,O->val); 
}

// special case handling for first clientHello after retry request
void runningSyntheticHash(octad *O,octad *E,unihash *h)
{
    int htype=h->htype; 
    unihash rhash;
    char hh[TLS_MAX_HASH];
    octad HH={0,sizeof(hh),hh};

    SAL_hashInit(htype,&rhash); 
 // RFC 8446 - "special synthetic message"
    runningHash(O,&rhash);
    runningHash(E,&rhash);
    transcriptHash(&rhash,&HH);
    
    SAL_hashProcess(h,MESSAGE_HASH);
    SAL_hashProcess(h,0); SAL_hashProcess(h,0);
    SAL_hashProcess(h,SAL_hashLen(htype));   // fe 00 00 sha
    
    runningHash(&HH,h);
}

// Initialise crypto context (Key,IV, Record number)
void initCryptoContext(crypto *C)
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
void updateCryptoContext(crypto *C,octad *K,octad *IV)
{ 
    OCT_copy(&(C->K),K);
    OCT_copy(&(C->IV),IV);
    C->record=0;
}

//  increment record, and update IV
void incrementCryptoContext(crypto *C)
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
void deriveVeriferData(int htype,octad *CF,octad *CHTS,octad *H)
{
    char fk[TLS_MAX_HASH];
    octad FK = {0,sizeof(fk),fk};
    char info[10];
    octad INFO = {0,sizeof(info),info};
    int hlen=SAL_hashLen(htype);
    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"finished");
    SAL_hkdfExpandLabel(htype,&FK,hlen,CHTS,&INFO,NULL); 
    SAL_hmac(htype,CF,&FK,H);
}

// check verification data
bool checkVeriferData(int htype,octad *SF,octad *SHTS,octad *H)
{
    char vd[TLS_MAX_HASH];
    octad VD = {0,sizeof(vd),vd};
    deriveVeriferData(htype,&VD,SHTS,H);
    return OCT_compare(SF,&VD);
}

// update Traffic secret and associated traffic key and IV
void deriveUpdatedKeys(crypto *context,octad *TS)
{
    int htype,sha,key;
    char info[16];
    octad INFO = {0,sizeof(info),info};
    char nts[TLS_MAX_HASH];
    octad NTS={0,sizeof(nts),nts};

// find cipher suite
    htype=SAL_hashType(context->suite);
    sha=SAL_hashLen(htype);

    key=context->K.len; // depends on key length

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"traffic upd");
    SAL_hkdfExpandLabel(htype,&NTS,sha,TS,&INFO,NULL);

    OCT_copy(TS,&NTS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    SAL_hkdfExpandLabel(htype,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    SAL_hkdfExpandLabel(htype,&(context->IV),12,TS,&INFO,NULL);
// reset record number
    context->record=0;
}

// Create a crypto context from an input raw Secret and an agreed cipher_suite 
void createCryptoContext(int cipher_suite,octad *TS,crypto *context)
{
    int key,htype=SAL_hashType(cipher_suite);
    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        key=TLS_AES_128;  // AES128
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        key=TLS_AES_256; // AES256
    }
    if (cipher_suite==TLS_CHACHA20_POLY1305_SHA256)
    {
        key=TLS_CHA_256; // IETF CHACHA20
    }
    char info[8];
    octad INFO = {0,sizeof(info),info};

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    SAL_hkdfExpandLabel(htype,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    SAL_hkdfExpandLabel(htype,&(context->IV),12,TS,&INFO,NULL);

    context->suite=cipher_suite;
    context->record=0;
}

// recover Pre-Shared-Key from Resumption Master Secret
void recoverPSK(int cipher_suite,octad *RMS,octad *NONCE,octad *PSK)
{
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int htype=SAL_hashType(cipher_suite);
    int hlen=SAL_hashLen(htype);
    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"resumption");
    SAL_hkdfExpandLabel(htype,PSK,hlen,RMS, &INFO, NONCE);
}

// Key Schedule code
// Get Early Secret ES and optional Binder Key (either External or Resumption)
void deriveEarlySecrets(int htype,octad *PSK,octad *ES,octad *BKE,octad *BKR)
{
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};  
    char zk[TLS_MAX_HASH];              
    octad ZK = {0,sizeof(zk),zk}; 
    char info[16];
    octad INFO = {0,sizeof(info),info};

    int hlen=SAL_hashLen(htype);

    OCT_append_byte(&ZK,0,hlen);  // Zero key

    if (PSK==NULL)
        OCT_copy(&EMH,&ZK);   // if no PSK available use ZK
    else
        OCT_copy(&EMH,PSK);

    SAL_hkdfExtract(htype,ES,&ZK,&EMH);  // hash function, ES is output, ZK is salt and EMH is IKM

    SAL_hashNull(htype,&EMH);  // EMH = hash of ""

    if (BKE!=NULL)
    {  // External Binder Key
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"ext binder");
        SAL_hkdfExpandLabel(htype,BKE,hlen,ES,&INFO,&EMH);
    }
    if (BKR!=NULL)
    { // Resumption Binder Key
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"res binder");
        SAL_hkdfExpandLabel(htype,BKR,hlen,ES,&INFO,&EMH);
    }
}

// Get Later Secrets (Client Early Traffic Secret CETS and Early Exporter Master Secret EEMS) - requires partial transcript hash H
void deriveLaterSecrets(int htype,octad *ES,octad *H,octad *CETS,octad *EEMS)
{
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int hlen=SAL_hashLen(htype);

    if (CETS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"c e traffic");
        SAL_hkdfExpandLabel(htype,CETS,hlen,ES,&INFO,H);
    }
    if (EEMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"e exp master");
        SAL_hkdfExpandLabel(htype,EEMS,hlen,ES,&INFO,H);
    }
}

// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
void deriveHandshakeSecrets(int htype,octad *SS,octad *ES,octad *H,octad *HS,octad *CHTS,octad *SHTS)
{
    char ds[TLS_MAX_HASH];
    octad DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int hlen=SAL_hashLen(htype);

    SAL_hashNull(htype,&EMH);      // hash of ""

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    SAL_hkdfExpandLabel(htype,&DS,hlen,ES,&INFO,&EMH);  

    SAL_hkdfExtract(htype,HS,&DS,SS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c hs traffic");
    SAL_hkdfExpandLabel(htype,CHTS,hlen,HS,&INFO,H);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s hs traffic");
    SAL_hkdfExpandLabel(htype,SHTS,hlen,HS,&INFO,H);
}

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
void deriveApplicationSecrets(int htype,octad *HS,octad *SFH,octad *CFH,octad *CTS,octad *STS,octad *EMS,octad *RMS)
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
    int hlen=SAL_hashLen(htype);

    OCT_append_byte(&ZK,0,hlen);           // 00..00  
    SAL_hashNull(htype,&EMH);  // hash("")

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    SAL_hkdfExpandLabel(htype,&DS,hlen,HS,&INFO,&EMH);   // Use handshake secret from above

    SAL_hkdfExtract(htype,&MS,&DS,&ZK);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c ap traffic");
    SAL_hkdfExpandLabel(htype,CTS,hlen,&MS,&INFO,SFH);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s ap traffic");
    SAL_hkdfExpandLabel(htype,STS,hlen,&MS,&INFO,SFH);

    if (EMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"exp master");
        SAL_hkdfExpandLabel(htype,EMS,hlen,&MS,&INFO,SFH);
    }
    if (RMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"res master");
        SAL_hkdfExpandLabel(htype,RMS,hlen,&MS,&INFO,CFH);
    }
}
