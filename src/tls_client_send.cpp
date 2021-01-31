// 
// Process output sent to Server
//
#include "tls_client_send.h"

// send Change Cipher Suite - helps get past middleboxes
void sendCCCS(int sock)
{
    char cccs[10];
    octet CCCS={0,sizeof(cccs),cccs};
    OCT_fromHex(&CCCS,(char *)"140303000101");
    sendOctet(sock,&CCCS);
}

// Functions to create clientHello Extensions based on our preferences/capabilities

// Build Servername Extension
void addServerNameExt(octet *EXT,char *servername)
{
    int len=strlen(servername);
    OCT_jint(EXT,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    OCT_jint(EXT,5+len,2);   // In theory its a list..
    OCT_jint(EXT,3+len,2);   // but only one entry
    OCT_jint(EXT,0,1);     // Server is of type DNS Hostname (only one type supported, and only one of each type)
    OCT_jint(EXT,len,2);   // serverName length
    OCT_jstring(EXT,servername); // servername
}
    
// Build Supported Groups Extension
void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups)
{
    OCT_jint(EXT,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    OCT_jint(EXT,2*nsg+2,2);          // Total length
    OCT_jint(EXT,2*nsg,2);            // Number of entries
    for (int i=0;i<nsg;i++)          // One entry per supported group 
        OCT_jint(EXT,supportedGroups[i],2);
}

// Build Signature algorithms Extension
void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs)
{
    OCT_jint(EXT,SIG_ALGS,2);  // This extension is SIGNATURE_ALGORITHMS(0x0d)
    OCT_jint(EXT,2*nsa+2,2);   // Total length
    OCT_jint(EXT,2*nsa,2);     // Number of entries
    for (int i=0;i<nsa;i++)   // One entry per supported signature algorithm
        OCT_jint(EXT,sigAlgs[i],2);
}

// Add Pre-Shared-Key vector...
// ..but omit bindings
int addPreSharedKeyExt(octet *EXT,int npsks,unsign32 age[],octet IDS[],int sha)
{
    int tlen1,tlen2;
    tlen1=tlen2=0;
    for (int i=0;i<npsks;i++)
    {
        tlen1+=IDS[i].len+2+4;
        tlen2+=sha+1;
    }
    OCT_jint(EXT,PRESHARED_KEY,2);
    OCT_jint(EXT,tlen1+tlen2+4,2);
// PSK Identifiers
    OCT_jint(EXT,tlen1,2);
    for (int i=0;i<npsks;i++)
    {
        OCT_jint(EXT,IDS[i].len,2);
        OCT_joctet(EXT,&IDS[i]);
        OCT_jint(EXT,age[i],4);
    }

    return tlen2+2;  // length of binders
// Bindings - Truncate Client Hello here
/*
    OCT_jint(&PSK,tlen2,2);
    for (int i=0;i<npsks;i++)
    {
        OCT_jint(&PSK,BNDS[i].len,1);
        OCT_joctet(&PSK,&BNDS[i]);
    }
*/
}

// Add Client Key Share extension
// Offer a choice of publics keys (some may be PQ!)
void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[])
{
    int tlen=0;
    for (int i=0;i<nalgs;i++)
        tlen+=PK[i].len+4;
    
    OCT_jint(EXT,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    OCT_jint(EXT,tlen+2,2);
    OCT_jint(EXT,tlen,2);
    for (int i=0;i<nalgs;i++)
    {
        OCT_jint(EXT,alg[i],2);
        OCT_jint(EXT,PK[i].len,2);
        OCT_joctet(EXT,&PK[i]);
    }
}

// indicate supported PSK mode
void addPSKExt(octet *EXT,int mode)
{
    OCT_jint(EXT,PSK_MODE,2);
    OCT_jint(EXT,2,2);
    OCT_jint(EXT,1,1);
    OCT_jint(EXT,mode,1);
}

// indicate prefered maximum fragment length
void addMFLExt(octet *EXT,int mode)
{
    OCT_jint(EXT,MAX_FRAG_LENGTH,2);
    OCT_jint(EXT,1,2);
    OCT_jint(EXT,mode,1);
}

// indicate TLS version support
void addVersionExt(octet *EXT,int version)
{
    OCT_jint(EXT,TLS_VER,2);
    OCT_jint(EXT,3,2);
    OCT_jint(EXT,2,1);
    OCT_jint(EXT,version,2);
}

// Add a cookie - useful for handshake resumption
void addCookieExt(octet *EXT,octet *CK)
{
    OCT_jint(EXT,COOKIE,2);
    OCT_jint(EXT,CK->len,2);
    OCT_joctet(EXT,CK);
}

// indicate desire to send early data
void addEarlyDataExt(octet *EXT)
{
    OCT_jint(EXT,EARLY_DATA,2);
    OCT_jint(EXT,0,2);
}

// Create 32-byte random octet
int clientRandom(octet *RN,csprng *RNG)
{
    OCT_rand(RN,RNG,32);
    return 32;
}

// Create random 32-byte session ID (not used in TLS1.3)
int sessionID(octet *SI,csprng *RNG)
{
    OCT_rand(SI,RNG,32);
    return 1+SI->len;  // return its overall length (extra byte required)
}

// build cipher-suites octet from ciphers we support
int cipherSuites(octet *CS,int ncs,int *ciphers)
{
    OCT_clear(CS);
    OCT_jint(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_jint(CS,ciphers[i],2);
    return CS->len;
}

// Send a client message CM (in a single record). AEAD encrypted if send!=NULL
void sendClientMessage(int sock,int rectype,int version,crypto *send,octet *CM,octet *RECORD)
{
    int reclen;
    char tag[TLS_TAG_SIZE];
    octet TAG={0,sizeof(tag),tag};

    OCT_clear(RECORD);
    if (send==NULL)
    { // no encryption
        OCT_jbyte(RECORD,rectype,1);
        OCT_jint(RECORD,version,2);
        reclen=CM->len;
        OCT_jint(RECORD,reclen,2);
        OCT_joctet(RECORD,CM); // CM->len
    } else { // encrypted, and sent as application record
        OCT_jbyte(RECORD,APPLICATION,1);
        OCT_jint(RECORD,TLS1_2,2);
        reclen=CM->len+16+1;       // 16 for the TAG, 1 for the record type
        OCT_jint(RECORD,reclen,2);
        OCT_joctet(RECORD,CM); 
        OCT_jbyte(RECORD,rectype,1); // append and encrypt actual record type
// could add random padding after this

// AES-GCM
        gcm g;
        GCM_init(&g,send->K.len,send->K.val,12,send->IV.val);  // Encrypt with Client Application Key and IV
        GCM_add_header(&g,RECORD->val,5);
        GCM_add_plain(&g,&RECORD->val[5],&RECORD->val[5],reclen-16);
//create and append TAG
        GCM_finish(&g,TAG.val); TAG.len=16;
// End AES-GCM
        increment_crypto_context(send);  // increment IV
        OCT_joctet(RECORD,&TAG);
    }
    sendOctet(sock,RECORD);     // transmit it
}

// build and transmit unencrypted client hello. Append pre-prepared extensions
void sendClientHello(int sock,int version,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS,int extra,octet *RECORD)
{
    char rn[32];
    octet RN = {0, sizeof(rn), rn};
    char cs[2+TLS_MAX_CIPHER_SUITES*2];
    octet CS = {0, sizeof(cs), cs};
    int compressionMethods=0x0100;
    int total=8;
    int extlen=EXTENSIONS->len+extra;
    total+=clientRandom(&RN,RNG);
    total+=sessionID(CID,RNG);
    total+=cipherSuites(&CS,nsc,ciphers);

    OCT_clear(CH);
    OCT_jbyte(CH,CLIENT_HELLO,1);  // clientHello handshake message  // 1
    OCT_jint(CH,total+extlen-2,3);   // 3

    OCT_jint(CH,TLS1_2,2);           // 2
    OCT_joctet(CH,&RN);              // 32
    OCT_jbyte(CH,CID->len,1);        // 1   
    OCT_joctet(CH,CID);              // 32
    OCT_joctet(CH,&CS);              // 2+TLS_MAX_CIPHER_SUITES*2
    OCT_jint(CH,compressionMethods,2);  // 2

    OCT_jint(CH,extlen,2);              // 2
    OCT_joctet(CH,EXTENSIONS);      // append extensions

// transmit it
    sendClientMessage(sock,HSHAKE,version,NULL,CH,RECORD);
}

// Send list of "binders", one per ticket
void sendBindersList(int sock,octet *B,int npsks,octet BNDS[],octet *RECORD)
{
    int tlen2=0;
    OCT_clear(B);
    for (int i=0;i<npsks;i++)
        tlen2+=BNDS[i].len+1;
    OCT_jint(B,tlen2,2);
    for (int i=0;i<npsks;i++)
    {
        OCT_jint(B,BNDS[i].len,1);
        OCT_joctet(B,&BNDS[i]);
    }
// transmit it
    sendClientMessage(sock,HSHAKE,TLS1_2,NULL,B,RECORD);

}

// send client alert - might be encrypted if send!=NULL
void sendClientAlert(int sock,int type,crypto *send,octet *RECORD)
{
    char pt[2];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,0x02,1);  // alerts are always fatal
    OCT_jbyte(&PT,type,1);  // alert type

    sendClientMessage(sock,ALERT,TLS1_2,send,&PT,RECORD);
}

// Send final client handshake verification data
void sendClientVerify(int sock,crypto *send,unihash *h,octet *CHF,octet *RECORD)
{
    char pt[TLS_MAX_HASH+4];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,FINISHED,1);  // indicates handshake message "client finished" 
    OCT_jint(&PT,CHF->len,3); // .. and its length 
    OCT_joctet(&PT,CHF);

    running_hash(&PT,h);

    sendClientMessage(sock,HSHAKE,TLS1_2,send,&PT,RECORD);
}

// if early data was accepted, send this to indicate early data is finished
void sendEndOfEarlyData(int sock,crypto *send,unihash *h,octet *RECORD)
{
    char ed[4];
    octet ED={0,sizeof(ed),ed};

    OCT_jbyte(&ED,END_OF_EARLY_DATA,1);
    OCT_jint(&ED,0,3);

    running_hash(&ED,h);

    sendClientMessage(sock,HSHAKE,TLS1_2,send,&ED,RECORD);
}

//
// map causes to alerts
//
int alert_from_cause(int rtn)
{
    switch (rtn)
    {
    case NOT_TLS1_3:
        return ILLEGAL_PARAMETER;
    case ID_MISMATCH:
        return ILLEGAL_PARAMETER;
    case UNRECOGNIZED_EXT:
        return ILLEGAL_PARAMETER;
    case BAD_HELLO:
        return ILLEGAL_PARAMETER;        
    case WRONG_MESSAGE:                 // Cause
        return UNEXPECTED_MESSAGE;      // Alert
    case BAD_CERT_CHAIN:                 // Cause
        return BAD_CERTIFICATE;      // Alert
    case MISSING_REQUEST_CONTEXT:
        return ILLEGAL_PARAMETER;
    case AUTHENTICATION_FAILURE:
        return DECRYPT_ERROR;
    case BAD_RECORD:
        return ILLEGAL_PARAMETER;
    case BAD_TICKET:
        return ILLEGAL_PARAMETER;
    default:
        return ILLEGAL_PARAMETER;    
    }
}

