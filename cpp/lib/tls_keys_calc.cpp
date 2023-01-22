//
// TLS1.3 crypto support functions (hashing, KDFs etc)
//

#include "tls_keys_calc.h"
#include "tls_logger.h"
#include "tls_x509.h"

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
    SAL_hashProcessArray(&session->tlshash,session->IBUFF.val,session->ptr);
}

// Shift octad left - rewind IO buffer to start 
void rewindIO(TLS_session *session)
{
    OCT_shift_left(&session->IBUFF,session->ptr);  
    session->ptr=0;
}

void runningHashIOrewind(TLS_session *session)
{
    runningHashIO(session);
    rewindIO(session);
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
    OCT_append_int(LB,length,2);					// 2
    OCT_append_byte(LB,(char)(6+Label->len),1);		// 1
    OCT_append_string(LB,(char *)"tls13 ");			// 6
    OCT_append_octad(LB,Label);						// Label->len
    if (CTX!=NULL)
    {
        OCT_append_byte(LB, (char)(CTX->len), 1);	// 1
        OCT_append_octad(LB,CTX);					// CTX->len
    } else {
        OCT_append_byte(LB,0,1);					// 1
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

    OCT_append_byte(&ZK,0,hlen);	// Zero key

    if (PSK==NULL)
        OCT_copy(&EMH,&ZK);			// if no PSK available use ZK
    else
        OCT_copy(&EMH,PSK);

    SAL_hkdfExtract(htype,ES,&ZK,&EMH);  // hash function, ES is output, ZK is salt and EMH is IKM

    SAL_hashNull(htype,&EMH);		// EMH = hash of ""

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
void deriveHandshakeSecrets(TLS_session *session,octad *SS,octad *ES,octad *H)
{
    char ds[TLS_MAX_HASH];
    octad DS = {0,sizeof(ds),ds};       // Derived Secret
    char emh[TLS_MAX_HASH];
    octad EMH = {0,sizeof(emh),emh};    // Empty Hash
    char info[16];
    octad INFO = {0,sizeof(info),info};
    int htype=SAL_hashType(session->cipher_suite);
    int hlen=SAL_hashLen(htype);

    SAL_hashNull(htype,&EMH);			// hash of ""

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    hkdfExpandLabel(htype,&DS,hlen,ES,&INFO,&EMH);  

    SAL_hkdfExtract(htype,&session->HS,&DS,SS);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"c hs traffic");
    hkdfExpandLabel(htype,&session->CTS,hlen,&session->HS,&INFO,H);

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"s hs traffic");
    hkdfExpandLabel(htype,&session->STS,hlen,&session->HS,&INFO,H);
}

// Extract Client and Server Application Traffic secrets from Transcript Hashes, Handshake secret 
// SFH - Server Finished Hash
// CFH - Client Finished Hash
void deriveApplicationSecrets(TLS_session *session,octad *SFH,octad *CFH,octad *EMS)
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

    OCT_append_byte(&ZK,0,hlen);			// 00..00  
    SAL_hashNull(htype,&EMH);				// hash("")

    OCT_kill(&INFO);
    OCT_append_string(&INFO,(char *)"derived");
    hkdfExpandLabel(htype,&DS,hlen,&session->HS,&INFO,&EMH);   // Use handshake secret from above

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

    if (sigAlg==DILITHIUM2_P256)
    {
        octad FKEY={32,32,KEY->val};
        octad SKEY={KEY->len-32,KEY->len-32,&KEY->val[32]};
        SAL_tlsSignature(ECDSA_SECP256R1_SHA384,&FKEY,&CCV,CCVSIG);
        ecdsa_sig_encode(CCVSIG);  // ASN.1 encode it - it grows
        octad SSIG={0,TLS_MAX_SIGNATURE_SIZE-32,&CCVSIG->val[CCVSIG->len]};
        SAL_tlsSignature(DILITHIUM2,&SKEY,&CCV,&SSIG); // append PQ sig
        CCVSIG->len += SSIG.len;
        return;
    }

    SAL_tlsSignature(sigAlg,KEY,&CCV,CCVSIG);
// adjustment for ECDSA signatures
    if (sigAlg==ECDSA_SECP256R1_SHA256 || sigAlg==ECDSA_SECP384R1_SHA384)
    {
        ecdsa_sig_encode(CCVSIG);
    }

    return;
}

// check that SCVSIG is digital signature (using sigAlg algorithm) of some TLS1.3 specific message+transcript hash, 
// as verified by Server Certificate public key CERTPK
bool checkServerCertVerifier(int sigAlg,octad *SCVSIG,octad *H,octad *CERTPK)
{
// Server Certificate Verify
    char scv[100+TLS_MAX_HASH];
    octad SCV={0,sizeof(scv),scv};

// TLS1.3 message that was signed
    OCT_append_byte(&SCV,32,64); // 64 spaces
    OCT_append_string(&SCV,(char *)"TLS 1.3, server CertificateVerify");  // 33 chars
    OCT_append_byte(&SCV,0,1);   // add 0 character
    OCT_append_octad(&SCV,H);    // add Transcript Hash 

    if (sigAlg==DILITHIUM2_P256)
    {
        octad FPUB={65,65,CERTPK->val};
        octad SPUB={CERTPK->len-65,CERTPK->len-65,&CERTPK->val[65]};
        int len=SCVSIG->len;   // full length
        int index=ecdsa_sig_decode(SCVSIG); // ASN.1 decode it - it shrinks - return undecoded length
        if (index==0) return false;
        int mlen=SCVSIG->len;               // modified length
        octad FSIG={mlen,mlen,SCVSIG->val};
        octad SSIG={len-index,len-index,&SCVSIG->val[index]};
        return SAL_tlsSignatureVerify(ECDSA_SECP256R1_SHA384,&SCV,&FSIG,&FPUB) && SAL_tlsSignatureVerify(DILITHIUM2,&SCV,&SSIG,&SPUB);
    }

// Special case processing required here for ECDSA signatures -  SCVSIG is modified
    if (sigAlg==ECDSA_SECP256R1_SHA256 || sigAlg==ECDSA_SECP384R1_SHA384) {
        if (!ecdsa_sig_decode(SCVSIG)) return false;
    }
    log(IO_DEBUG,(char *)"Certificate Signature = ",NULL,0,SCVSIG);
    return SAL_tlsSignatureVerify(sigAlg,&SCV,SCVSIG,CERTPK);
}
