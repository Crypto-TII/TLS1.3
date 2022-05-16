//
// TLS1.3 crypto support functions (hashing, KDFs etc)
//

#include "tls_keys_calc.h"
#include "tls_logger.h"

// Initialise transcript hash
void initTranscriptHash(TLS_session *session)
{
    int hashtype=SAL_hashType(session->cipher_suite);
    SAL_hashInit(hashtype,&session->tlshash);
}

// Add octad to transcript hash 
void runningHash(TLS_session *session,octad *O)
{
    SAL_hashProcessArray(&session->tlshash,O->val,O->len);
}

// Add IO buffer to transcript hash
void runningHashIO(TLS_session *session)
{
    SAL_hashProcessArray(&session->tlshash,session->IO.val,session->ptr);
    OCT_shift_left(&session->IO,session->ptr);  // Shift octad left - rewind IO buffer to start 
    session->ptr=0;
}

// Output transcript hash 
void transcriptHash(TLS_session *session,octad *O)
{
    O->len=SAL_hashOutput(&session->tlshash,O->val); 
}

// special case handling for first clientHello after retry request
void runningSyntheticHash(TLS_session *session,octad *O,octad *E)
{
    int htype=session->tlshash.htype; 
    unihash rhash;
    char hh[TLS_MAX_HASH];
    octad HH={0,sizeof(hh),hh};

    SAL_hashInit(htype,&rhash); 
 // RFC 8446 - "special synthetic message"
    SAL_hashProcessArray(&rhash,O->val,O->len);
    SAL_hashProcessArray(&rhash,E->val,E->len);

    //runningHash(O,&rhash);
    //runningHash(E,&rhash);
    HH.len=SAL_hashOutput(&rhash,HH.val);
    
    char t[4];
    t[0]=MESSAGE_HASH;
    t[1]=t[2]=0;
    t[3]=SAL_hashLen(htype);
    SAL_hashProcessArray(&session->tlshash,t,4);
    
    runningHash(session,&HH);
}

// Initialise crypto context (Key,IV, Record number)
void initCryptoContext(crypto *C)
{
    C->active=false;

    C->K.len = 0;
    C->K.max = TLS_MAX_KEY;
    C->K.val = C->k;

    C->IV.len = 0;
    C->IV.max = 12;
    C->IV.val = C->iv;

    C->suite=TLS_AES_128_GCM_SHA256; // default
    C->record=0;
	C->taglen=16;  // default
}

// Fill a crypto context with new key/IV
void updateCryptoContext(crypto *C,octad *K,octad *IV)
{ 
    C->active=true;
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

// create expanded HKDF label LB from label and context
static void hkdfLabel(octad *LB,int length,octad *Label,octad *CTX)
{
    OCT_append_int(LB,length,2);    // 2
    OCT_append_byte(LB,(char)(6+Label->len),1);  // 1
    OCT_append_string(LB,(char *)"tls13 ");   // 6
    OCT_append_octad(LB,Label);  // Label->len
    if (CTX!=NULL)
    {
        OCT_append_byte(LB, (char)(CTX->len), 1); // 1
        OCT_append_octad(LB,CTX);   // CTX->len
    } else {
        OCT_append_byte(LB,0,1);   // 1
    }
}

// HKDF extension for TLS1.3
static void hkdfExpandLabel(int htype,octad *OKM,int olen,octad *PRK,octad *Label,octad *CTX)
{
    char hl[TLS_MAX_HASH+24];
    octad HL={0,sizeof(hl),hl};
    hkdfLabel(&HL,olen,Label,CTX);
    SAL_hkdfExpand(htype,olen,OKM,PRK,&HL);
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
    hkdfExpandLabel(htype,&FK,hlen,CHTS,&INFO,NULL); 
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

    key=SAL_aeadKeylen(context->suite); // depends on key length

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"traffic upd");
    hkdfExpandLabel(htype,&NTS,sha,TS,&INFO,NULL);

    OCT_copy(TS,&NTS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    hkdfExpandLabel(htype,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    hkdfExpandLabel(htype,&(context->IV),12,TS,&INFO,NULL);
// reset record number
    context->record=0;
    context->active=true;
}

// Create a crypto context from an input raw Secret and an agreed cipher_suite 
void createCryptoContext(int cipher_suite,octad *TS,crypto *context)
{
    int key,htype=SAL_hashType(cipher_suite);

	key=SAL_aeadKeylen(cipher_suite);

    char info[8];
    octad INFO = {0,sizeof(info),info};

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"key");
    hkdfExpandLabel(htype,&(context->K),key,TS,&INFO,NULL);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"iv");
    hkdfExpandLabel(htype,&(context->IV),12,TS,&INFO,NULL);

    context->active=true;
    context->suite=cipher_suite;
    context->record=0;
	context->taglen=SAL_aeadTaglen(cipher_suite);
}

void createSendCryptoContext(TLS_session *session,octad *TS)
{
    createCryptoContext(session->cipher_suite,TS,&session->K_send);
}

void createRecvCryptoContext(TLS_session *session,octad *TS)
{
    createCryptoContext(session->cipher_suite,TS,&session->K_recv);
}

// recover Pre-Shared-Key from Resumption Master Secret
void recoverPSK(TLS_session *session)
{
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int htype=SAL_hashType(session->cipher_suite);
    int hlen=SAL_hashLen(htype);
    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"resumption");
    hkdfExpandLabel(htype,&session->T.PSK,hlen,&session->RMS, &INFO, &session->T.NONCE);
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
        hkdfExpandLabel(htype,BKE,hlen,ES,&INFO,&EMH);
    }
    if (BKR!=NULL)
    { // Resumption Binder Key
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"res binder");
        hkdfExpandLabel(htype,BKR,hlen,ES,&INFO,&EMH);
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
        hkdfExpandLabel(htype,CETS,hlen,ES,&INFO,H);
    }
    if (EEMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"e exp master");
        hkdfExpandLabel(htype,EEMS,hlen,ES,&INFO,H);
    }
}

// get Client and Server Handshake secrets for encrypting rest of handshake, from Shared secret SS and early secret ES
void deriveHandshakeSecrets(TLS_session *session,octad *SS,octad *ES,octad *H,octad *HS)
{
    char ds[TLS_MAX_HASH];
    octad DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int htype=SAL_hashType(session->cipher_suite);
    int hlen=SAL_hashLen(htype);

    SAL_hashNull(htype,&EMH);      // hash of ""

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    hkdfExpandLabel(htype,&DS,hlen,ES,&INFO,&EMH);  

    SAL_hkdfExtract(htype,HS,&DS,SS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c hs traffic");
    hkdfExpandLabel(htype,&session->CTS,hlen,HS,&INFO,H);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s hs traffic");
    hkdfExpandLabel(htype,&session->STS,hlen,HS,&INFO,H);
}

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
void deriveApplicationSecrets(TLS_session *session,octad *HS,octad *SFH,octad *CFH,octad *EMS)
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
    int htype=SAL_hashType(session->cipher_suite);
    int hlen=SAL_hashLen(htype);

    OCT_append_byte(&ZK,0,hlen);           // 00..00  
    SAL_hashNull(htype,&EMH);  // hash("")

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    hkdfExpandLabel(htype,&DS,hlen,HS,&INFO,&EMH);   // Use handshake secret from above

    SAL_hkdfExtract(htype,&MS,&DS,&ZK);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c ap traffic");
    hkdfExpandLabel(htype,&session->CTS,hlen,&MS,&INFO,SFH);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s ap traffic");
    hkdfExpandLabel(htype,&session->STS,hlen,&MS,&INFO,SFH);

    if (EMS!=NULL)
    {
        OCT_kill(&INFO);
        OCT_append_string(&INFO,(char *)"exp master");
        hkdfExpandLabel(htype,EMS,hlen,&MS,&INFO,SFH);
    }

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"res master");
    hkdfExpandLabel(htype,&session->RMS,hlen,&MS,&INFO,CFH);
}

// Convert ECDSA signature to DER encoded form
static void parse_in_ecdsa_sig(int sha,octad *CCVSIG)
{ // parse ECDSA signature into DER encoded (r,s) form
	int shalen=SAL_hashLen(sha);
    char c[TLS_MAX_ECC_FIELD];
    octad C={0,sizeof(c),c};
    char d[TLS_MAX_ECC_FIELD];
    octad D={0,sizeof(d),d};
    int len,clen=shalen;
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
    if (sigAlg==ECDSA_SECP256R1_SHA256 || sigAlg==ECDSA_SECP384R1_SHA384)
        parse_in_ecdsa_sig(SAL_hashTypeSig(sigAlg),CCVSIG);

    return;
}

// Convert DER encoded signature to ECDSA signature
static bool parse_out_ecdsa_sig(int sha,octad *SCVSIG)
{ // parse out DER encoded (r,s) ECDSA signature into a single SIG 
    ret rt;
    int lzero,der,rlen,slen,Int,ptr=0;
    int len=SCVSIG->len;
	int shalen=SAL_hashLen(sha);
    char r[TLS_MAX_ECC_FIELD];
    octad R={0,sizeof(r),r};
    char s[TLS_MAX_ECC_FIELD];
    octad S={0,sizeof(s),s};

    rt=parseInt(SCVSIG,1,ptr); der=rt.val;
    if (rt.err || der!=0x30) return false;
    rt=parseInt(SCVSIG,1,ptr); slen=rt.val;
    if (rt.err || slen+2!=len) return false;

// get R
    rt=parseInt(SCVSIG,1,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseInt(SCVSIG,1,ptr); rlen=rt.val;
    if (rt.err) return false;
    if (rlen==shalen+1)
    { // one too big
        rlen--;
        rt=parseInt(SCVSIG,1,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&R,shalen,SCVSIG,ptr); if (rt.err) return false;

// get S
    rt=parseInt(SCVSIG,1,ptr); Int=rt.val;
    if (rt.err || Int!=0x02) return false;
    rt=parseInt(SCVSIG,1,ptr); slen=rt.val;
    if (rt.err) return false;
    if (slen==shalen+1)
    { // one too big
        slen--;
        rt=parseInt(SCVSIG,1,ptr); lzero=rt.val;
        if (rt.err || lzero!=0) return false;
    }
    rt=parseoctad(&S,shalen,SCVSIG,ptr); if (rt.err) return false;

    if (rlen<shalen || slen<shalen) return false;

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
    if (sigAlg==ECDSA_SECP256R1_SHA256 || sigAlg==ECDSA_SECP384R1_SHA384) {
        if (!parse_out_ecdsa_sig(SAL_hashTypeSig(sigAlg),SCVSIG)) return false;
    }
    log(IO_DEBUG,(char *)"Certificate Signature = ",NULL,0,SCVSIG);
    return SAL_tlsSignatureVerify(sigAlg,&SCV,SCVSIG,CERTPK);
}

