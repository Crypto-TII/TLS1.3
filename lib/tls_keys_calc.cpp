//
// TLS1.3 crypto support functions (hashing, KDFs etc)
//

#include "tls_keys_calc.h"

// Add octad to transcript hash 
void runningHash(octad *O,unihash *h)
{
    SAL_hashProcessArray(h,O->val,O->len);
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
    
    char t[4];
    t[0]=MESSAGE_HASH;
    t[1]=t[2]=0;
    t[3]=SAL_hashLen(htype);
    SAL_hashProcessArray(h,t,4);
    
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

// Convert ECDSA signature to DER encoded form
static void parse_in_ecdsa_sig(int sha,octad *CCVSIG)
{ // parse ECDSA signature into DER encoded (r,s) form
    char c[TLS_MAX_ECC_FIELD];
    octad C={0,sizeof(c),c};
    char d[TLS_MAX_ECC_FIELD];
    octad D={0,sizeof(d),d};
    int len,clen=sha;
    bool cinc=false;
    bool dinc=false;

    C.len=D.len=clen;
    for (int i=0;i<clen;i++)
    {
        C.val[i]=CCVSIG->val[i];
        D.val[i]=CCVSIG->val[clen+i];
    }

    if (C.val[0]&0x80) cinc=true;
    if (D.val[0]&0x80) dinc=true;

    len=2*clen+4;
    if (cinc) len++;    // -ve values need leading zero inserted
    if (dinc) len++;

    OCT_kill(CCVSIG);
    OCT_append_byte(CCVSIG,0x30,1);  // ASN.1 SEQ
    OCT_append_byte(CCVSIG,len,1);
// C
    OCT_append_byte(CCVSIG,0x02,1);  // ASN.1 INT type
    if (cinc)
    {
        OCT_append_byte(CCVSIG,clen+1,1);
        OCT_append_byte(CCVSIG,0,1);
    } else {
        OCT_append_byte(CCVSIG,clen,1);
    }
    OCT_append_octad(CCVSIG,&C);
// D
    OCT_append_byte(CCVSIG,0x02,1);  // ASN.1 INT type
    if (dinc)
    {
        OCT_append_byte(CCVSIG,clen+1,1);
        OCT_append_byte(CCVSIG,0,1);
    } else {
        OCT_append_byte(CCVSIG,clen,1);
    }
    OCT_append_octad(CCVSIG,&D);
}

// Create Client Cert Verify message, a digital signature using KEY on some TLS1.3 specific message+transcript hash
void createClientCertVerifier(int sigAlg,octad *H,octad *KEY,octad *CCVSIG)
{
    char ccv[100+TLS_MAX_HASH];
    octad CCV={0,sizeof(ccv),ccv};
// create TLS1.3 message to be signed
    OCT_append_byte(&CCV,32,64); // 64 spaces
    OCT_append_string(&CCV,(char *)"TLS 1.3, client CertificateVerify");  // 33 chars
    OCT_append_byte(&CCV,0,1);   // add 0 character
    OCT_append_octad(&CCV,H);    // add Transcript Hash 

    SAL_tlsSignature(sigAlg,KEY,&CCV,CCVSIG);

// adjustment for ECDSA signatures
    if (sigAlg==ECDSA_SECP256R1_SHA256)
        parse_in_ecdsa_sig(TLS_SHA256,CCVSIG);
    if (sigAlg==ECDSA_SECP384R1_SHA384)
        parse_in_ecdsa_sig(TLS_SHA384,CCVSIG);

    return;
}

// Convert DER encoded signature to ECDSA signature
static bool parse_out_ecdsa_sig(int sha,octad *SCVSIG)
{ // parse out DER encoded (r,s) ECDSA signature into a single SIG 
    ret rt;
    int lzero,der,rlen,slen,Int,ptr=0;
    int len=SCVSIG->len;
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};

    rt=parseByte(SCVSIG,ptr); der=rt.val;
    if (rt.err || der!=0x30) return false;
    rt=parseByte(SCVSIG,ptr); slen=rt.val;
    if (rt.err || slen+2!=len) return false;

// get R
    rt=parseByte(SCVSIG,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseByte(SCVSIG,ptr); rlen=rt.val;
    if (rt.err) return false;
    if (rlen==sha+1)
    { // one too big
        rlen--;
        rt=parseByte(SCVSIG,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&R,sha,SCVSIG,ptr); if (rt.err) return false;

// get S
    rt=parseByte(SCVSIG,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseByte(SCVSIG,ptr); slen=rt.val;
    if (rt.err || slen==sha+1)
    { // one too big
        slen--;
        rt=parseByte(SCVSIG,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&S,sha,SCVSIG,ptr); if (rt.err) return false;

    if (rlen<sha || slen<sha) return false;

    OCT_copy(SCVSIG,&R);
    OCT_append_octad(SCVSIG,&S);
    return true;
}

// check that SCVSIG is digital signature (using sigAlg algorithm) of some TLS1.3 specific message+transcript hash, 
// as verified by Server Certificate public key CERTPK

bool checkServerCertVerifier(int sigAlg,octad *SCVSIG,octad *H,octad *CERTPK)
{
// Server Certificate Verify
    ret rt;
    int lzero,sha;
    char scv[100+TLS_MAX_HASH];
    octad SCV={0,sizeof(scv),scv};
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};
    char sig[2*TLS_MAX_ECC_FIELD];
    octad SIG={0,sizeof(sig),sig};

// TLS1.3 message that was signed
    OCT_append_byte(&SCV,32,64); // 64 spaces
    OCT_append_string(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_append_byte(&SCV,0,1);   // add 0 character
    OCT_append_octad(&SCV,H);    // add Transcript Hash 

// Special case processing required here for ECDSA signatures -  SCVSIG is modified
    if (sigAlg==ECDSA_SECP256R1_SHA256) {
        if (!parse_out_ecdsa_sig(TLS_SHA256,SCVSIG)) return false;
    }
    if (sigAlg==ECDSA_SECP384R1_SHA384) {
        if (!parse_out_ecdsa_sig(TLS_SHA384,SCVSIG)) return false;
    } 

#if VERBOSITY >= IO_DEBUG
        logger((char *)"Certificate Signature = \n",NULL,0,SCVSIG);
        logger((char *)"Public Key = \n",NULL,0,CERTPK);
#endif

    return SAL_tlsSignatureVerify(sigAlg,&SCV,SCVSIG,CERTPK);
}
