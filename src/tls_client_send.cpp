// 
// Process output sent to Server
//

#include "tls_client_send.h"
#include "tls_logger.h"

// send Change Cipher Suite - helps get past middleboxes
void sendCCCS(Socket &client)
{
    char cccs[10];
    octad CCCS={0,sizeof(cccs),cccs};
    OCT_from_hex(&CCCS,(char *)"140303000101");
    sendOctad(client,&CCCS);
}

// Functions to build clientHello Extensions based on our preferences/capabilities

// Build Servername Extension
void addServerNameExt(octad *EXT,char *servername)
{
    int len=strlen(servername);
    OCT_append_int(EXT,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    OCT_append_int(EXT,5+len,2);   // In theory its a list..
    OCT_append_int(EXT,3+len,2);   // but only one entry
    OCT_append_int(EXT,0,1);     // Server is of type DNS Hostname (only one type supported, and only one of each type)
    OCT_append_int(EXT,len,2);   // serverName length
    OCT_append_string(EXT,servername); // servername
}
    
// Build Supported Groups Extension
void addSupportedGroupsExt(octad *EXT,int nsg,int *supportedGroups)
{
    OCT_append_int(EXT,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    OCT_append_int(EXT,2*nsg+2,2);          // Total length
    OCT_append_int(EXT,2*nsg,2);            // Number of entries
    for (int i=0;i<nsg;i++)          // One entry per supported group 
        OCT_append_int(EXT,supportedGroups[i],2);
}

// Build Signature algorithms Extension
void addSigAlgsExt(octad *EXT,int nsa,int *sigAlgs)
{
    OCT_append_int(EXT,SIG_ALGS,2);  // This extension is SIGNATURE_ALGORITHMS(0x0d)
    OCT_append_int(EXT,2*nsa+2,2);   // Total length
    OCT_append_int(EXT,2*nsa,2);     // Number of entries
    for (int i=0;i<nsa;i++)   // One entry per supported signature algorithm
        OCT_append_int(EXT,sigAlgs[i],2);
}

// Build Signature algorithms Cert Extension
void addSigAlgsCertExt(octad *EXT,int nsac,int *sigAlgsCert)
{
    OCT_append_int(EXT,SIG_ALGS_CERT,2);  // This extension is SIGNATURE_ALGORITHMS_CERT (0x32)
    OCT_append_int(EXT,2*nsac+2,2);   // Total length
    OCT_append_int(EXT,2*nsac,2);     // Number of entries
    for (int i=0;i<nsac;i++)   // One entry per supported signature algorithm
        OCT_append_int(EXT,sigAlgsCert[i],2);
}

// Add Pre-Shared-Key ...
// ..but omit binding
int addPreSharedKeyExt(octad *EXT,unsign32 age,octad *IDS,int sha)
{
    int tlen1,tlen2;
    tlen1=tlen2=0;
    tlen1+=IDS->len+2+4;
    tlen2+=sha+1;
    OCT_append_int(EXT,PRESHARED_KEY,2);
    OCT_append_int(EXT,tlen1+tlen2+4,2);
// PSK Identifiers
    OCT_append_int(EXT,tlen1,2);
    OCT_append_int(EXT,IDS->len,2);
    OCT_append_octad(EXT,IDS);
    OCT_append_int(EXT,age,4);
    return tlen2+2;  // length of binders
}

// Add Client Key Share extension
// Offer just one public key
void addKeyShareExt(octad *EXT,int alg,octad *PK)
{
    int tlen=PK->len+4;
    OCT_append_int(EXT,KEY_SHARE,2); // This extension is KEY_SHARE(0x0033)
    OCT_append_int(EXT,tlen+2,2);
    OCT_append_int(EXT,tlen,2);
    OCT_append_int(EXT,alg,2);
    OCT_append_int(EXT,PK->len,2);
    OCT_append_octad(EXT,PK);
}

// indicate supported PSK mode
void addPSKModesExt(octad *EXT,int mode)
{
    OCT_append_int(EXT,PSK_MODE,2);
    OCT_append_int(EXT,2,2);
    OCT_append_int(EXT,1,1);
    OCT_append_int(EXT,mode,1);
}

// indicate prefered maximum fragment length
void addMFLExt(octad *EXT,int mode)
{
    OCT_append_int(EXT,MAX_FRAG_LENGTH,2);
    OCT_append_int(EXT,1,2);
    OCT_append_int(EXT,mode,1);
}

// add n padding bytes
void addPadding(octad *EXT,int n)
{
    OCT_append_int(EXT,PADDING,2);
    OCT_append_int(EXT,n,2);
    OCT_append_byte(EXT,0,n);
}

// indicate TLS version support
void addVersionExt(octad *EXT,int version)
{
    OCT_append_int(EXT,TLS_VER,2);
    OCT_append_int(EXT,3,2);
    OCT_append_int(EXT,2,1);
    OCT_append_int(EXT,version,2);
}

// Add a cookie - useful for handshake resumption
void addCookieExt(octad *EXT,octad *CK)
{
    OCT_append_int(EXT,COOKIE,2);
    OCT_append_int(EXT,CK->len,2);
    OCT_append_octad(EXT,CK);
}

// indicate desire to send early data
void addEarlyDataExt(octad *EXT)
{
    OCT_append_int(EXT,EARLY_DATA,2);
    OCT_append_int(EXT,0,2);
}

// Create 32-byte random octad
int clientRandom(octad *RN)
{
    TLS_RANDOM_OCTAD(32,RN);
    return 32;
}

// Create random 32-byte session ID (not used in TLS1.3)
int sessionID(octad *SI)
{
    TLS_RANDOM_OCTAD(32,SI);
    return 1+SI->len;  // return its overall length (extra byte required)
}

// build cipher-suites octad from ciphers we support
int cipherSuites(octad *CS,int ncs,int *ciphers)
{
    OCT_kill(CS);
    OCT_append_int(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_append_int(CS,ciphers[i],2);
    return CS->len;
}

// ALL Client to Server output goes via this function 
// Send a client message CM|EXT (as a single record). AEAD encrypted if send!=NULL
void sendClientMessage(Socket &client,int rectype,int version,crypto *send,octad *CM,octad *EXT,octad *IO)
{
    int reclen;
    char tag[TLS_TAG_SIZE];
    octad TAG={0,sizeof(tag),tag};

    int rbytes=TLS_RANDOM_BYTE()%16; // random padding bytes

    OCT_kill(IO);
    reclen=CM->len;
    if (EXT!=NULL) reclen+=EXT->len;
    if (send==NULL)
    { // no encryption
        OCT_append_byte(IO,rectype,1);
        OCT_append_int(IO,version,2);
        OCT_append_int(IO,reclen,2);
        OCT_append_octad(IO,CM); // CM->len
        if (EXT!=NULL) OCT_append_octad(IO,EXT);
    } else { // encrypted, and sent disguised as application record
        OCT_append_byte(IO,APPLICATION,1);
        OCT_append_int(IO,TLS1_2,2);
        reclen+=16+1+rbytes; // 16 for the TAG, 1 for the record type, + some random padding
        OCT_append_int(IO,reclen,2);
        OCT_append_octad(IO,CM); 
        if (EXT!=NULL) OCT_append_octad(IO,EXT);
        OCT_append_byte(IO,rectype,1); // append and encrypt actual record type
// add some random padding after this...
        OCT_append_byte(IO,0,rbytes);

        AES_GCM_ENCRYPT(send,5,&IO->val[0],reclen-16,&IO->val[5],&TAG);

        increment_crypto_context(send);  // increment IV
        OCT_append_octad(IO,&TAG);
    }
    sendOctad(client,IO);     // transmit it
}

// build and transmit unencrypted client hello. Append pre-prepared extensions
void sendClientHello(Socket &client,int version,octad *CH,int nsc,int *ciphers,octad *CID,octad *EXTENSIONS,int extra,octad *IO)
{
    char rn[32];
    octad RN = {0, sizeof(rn), rn};
    char cs[2+TLS_MAX_CIPHER_SUITES*2];
    octad CS = {0, sizeof(cs), cs};
    int compressionMethods=0x0100;
    int total=8;
    int extlen=EXTENSIONS->len+extra;
    total+=clientRandom(&RN);
    total+=sessionID(CID);
    total+=cipherSuites(&CS,nsc,ciphers);

    OCT_kill(CH);
    OCT_append_byte(CH,CLIENT_HELLO,1);  // clientHello handshake message  // 1
    OCT_append_int(CH,total+extlen-2,3);   // 3

    OCT_append_int(CH,TLS1_2,2);           // 2
    OCT_append_octad(CH,&RN);              // 32
    OCT_append_byte(CH,CID->len,1);        // 1   
    OCT_append_octad(CH,CID);              // 32
    OCT_append_octad(CH,&CS);              // 2+TLS_MAX_CIPHER_SUITES*2
    OCT_append_int(CH,compressionMethods,2);  // 2

    OCT_append_int(CH,extlen,2);              // 2

// transmit it
    sendClientMessage(client,HSHAKE,version,NULL,CH,EXTENSIONS,IO);
}

// Send "binder",
void sendBinder(Socket &client,octad *B,octad *BND,octad *IO)
{
    int tlen2=0;
    OCT_kill(B);
    tlen2+=BND->len+1;
    OCT_append_int(B,tlen2,2);
    OCT_append_int(B,BND->len,1);
    OCT_append_octad(B,BND);
    sendClientMessage(client,HSHAKE,TLS1_2,NULL,B,NULL,IO);
}

// send client alert - might be encrypted if send!=NULL
void sendClientAlert(Socket &client,int type,crypto *send,octad *IO)
{
    char pt[2];
    octad PT={0,sizeof(pt),pt};
    OCT_append_byte(&PT,0x02,1);  // alerts are always fatal
    OCT_append_byte(&PT,type,1);  // alert type
    sendClientMessage(client,ALERT,TLS1_2,send,&PT,NULL,IO);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Failure - Alert sent to Server ",(char *)"%d",type,NULL);
#endif
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Client to Server -> ",NULL,0,IO);
#endif
}

// Send final client handshake verification data
void sendClientFinish(Socket &client,crypto *send,unihash *h,octad *CHF,octad *IO)
{
    char pt[4];
    octad PT={0,sizeof(pt),pt};

    OCT_append_byte(&PT,FINISHED,1);  // indicates handshake message "client finished" 
    OCT_append_int(&PT,CHF->len,3); // .. and its length 

    running_hash(&PT,h);
    running_hash(CHF,h);
    sendClientMessage(client,HSHAKE,TLS1_2,send,&PT,CHF,IO);
}

/* Send Client Cert Verify */
void sendClientCertVerify(Socket &client,crypto *send, unihash *h, int sigAlg, octad *CCVSIG,octad *IO)
{
    char pt[10];
    octad PT{0,sizeof(pt),pt};
    OCT_append_byte(&PT,CERT_VERIFY,1);
    OCT_append_int(&PT,4+CCVSIG->len,3);
    OCT_append_int(&PT,sigAlg,2);
    OCT_append_int(&PT,CCVSIG->len,2);
    running_hash(&PT,h);
    running_hash(CCVSIG,h);
    sendClientMessage(client,HSHAKE,TLS1_2,send,&PT,CCVSIG,IO);
}

// Send Client Certificate 
void sendClientCertificateChain(Socket &client,crypto *send, unihash *h,octad *CERTCHAIN,octad *IO)
{
    char pt[10];
    octad PT{0,sizeof(pt),pt};

    OCT_append_byte(&PT,CERTIFICATE,1);
    if (CERTCHAIN==NULL) {  // no acceptable certificate available
        OCT_append_int(&PT,4,3);
        OCT_append_byte(&PT,0,1); // cert context
        OCT_append_int(&PT,0,3);  // zero length
        running_hash(&PT,h);
    } else {
        OCT_append_int(&PT,4+CERTCHAIN->len,3);
        OCT_append_byte(&PT,0,1); // cert context
        OCT_append_int(&PT,CERTCHAIN->len,3);  // length of certificate chain
        running_hash(&PT,h);
        running_hash(CERTCHAIN,h);
    }
    sendClientMessage(client,HSHAKE,TLS1_2,send,&PT,CERTCHAIN,IO);
} 

// if early data was accepted, send this to indicate early data is finished
void sendEndOfEarlyData(Socket &client,crypto *send,unihash *h,octad *IO)
{
    char ed[4];
    octad ED={0,sizeof(ed),ed};
    OCT_append_byte(&ED,END_OF_EARLY_DATA,1);
    OCT_append_int(&ED,0,3);
    running_hash(&ED,h);
    sendClientMessage(client,HSHAKE,TLS1_2,send,&ED,NULL,IO);
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
    case BAD_CERT_CHAIN:                // Cause
        return BAD_CERTIFICATE;         // Alert
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

