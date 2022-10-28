// 
// Process output sent to Server
//

#include "tls_client_send.h"
#include "tls_logger.h"

// send Change Cipher Suite - helps get past middleboxes
void sendCCCS(TLS_session *session)
{
    char cccs[10];
    octad CCCS={0,sizeof(cccs),cccs};
    OCT_from_hex(&CCCS,(char *)"140303000101");
    sendOctad(session->sockptr,&CCCS);
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

// Add ALPN extension
// Offer just one option
void addALPNExt(octad *EXT,octad *AP)
{
    int tlen=AP->len+1;
    OCT_append_int(EXT,APP_PROTOCOL,2);
    OCT_append_int(EXT,tlen+2,2);
    OCT_append_int(EXT,tlen,2);
    OCT_append_int(EXT,AP->len,1);
    OCT_append_octad(EXT,AP);
}

// indicate supported PSK mode
void addPSKModesExt(octad *EXT,int mode)
{
    OCT_append_int(EXT,PSK_MODE,2);
    OCT_append_int(EXT,2,2);
    OCT_append_int(EXT,1,1);
    OCT_append_int(EXT,mode,1);
}

// indicate preferred maximum fragment length
void addMFLExt(octad *EXT,int mode)
{
	if (mode>0)
	{
		OCT_append_int(EXT,MAX_FRAG_LENGTH,2);
		OCT_append_int(EXT,1,2);
		OCT_append_int(EXT,mode,1);
	}
}

// indicate preferred maximum record size
void addRSLExt(octad *EXT,int size)
{
    OCT_append_int(EXT,RECORD_SIZE_LIMIT,2);
    OCT_append_int(EXT,2,2);
    OCT_append_int(EXT,size,2);
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
/*
int clientRandom(octad *RN)
{
    SAL_randomOctad(32,RN);
    return 32;
}
*/

// build cipher-suites octad from ciphers we support
int cipherSuites(octad *CS,int ncs,int *ciphers)
{
    OCT_kill(CS);
    OCT_append_int(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_append_int(CS,ciphers[i],2);
    return CS->len;
}

// flush out IO buffer
void sendFlushIO(TLS_session *session)
{
    sendOctad(session->sockptr,&session->IO);     // transmit it
    OCT_kill(&session->IO);
    session->ptr=0;
}

// ALL Client to Server output goes via this function 
// Send a client message CM|EXT (as a single record). AEAD encrypted if send!=NULL
// May need to break up into multiple records??
void sendClientMessage(TLS_session *session,int rectype,int version,octad *CM,octad *EXT,bool flush)
{
    int reclen,taglen;
    char tag[TLS_MAX_TAG_SIZE];
    octad TAG={0,sizeof(tag),tag};

    if (session->status==TLS13_DISCONNECTED) {
        OCT_kill(&session->IO);
        session->ptr=0;
        return;
    }

    int rbytes=SAL_randomByte()%16; // random padding bytes

    //OCT_kill(&session->IO);
    //session->ptr=0;

    reclen=CM->len;
    if (EXT!=NULL) reclen+=EXT->len;
    if (!session->K_send.active)
    { // no encryption
        OCT_append_byte(&session->IO,rectype,1);
        OCT_append_int(&session->IO,version,2);
        OCT_append_int(&session->IO,reclen,2);

        OCT_append_octad(&session->IO,CM); // CM->len
        if (EXT!=NULL) OCT_append_octad(&session->IO,EXT);
    } else { // encrypted, and sent disguised as application record
        OCT_append_byte(&session->IO,APPLICATION,1);
        OCT_append_int(&session->IO,TLS1_2,2);
		taglen=session->K_send.taglen;
        reclen+=taglen+1+rbytes; // 16 for the TAG, 1 for the record type, + some random padding
        OCT_append_int(&session->IO,reclen,2);

        OCT_append_octad(&session->IO,CM); 
        if (EXT!=NULL) OCT_append_octad(&session->IO,EXT);
        OCT_append_byte(&session->IO,rectype,1); // append and encrypt actual record type
// add some random padding after this...
        OCT_append_byte(&session->IO,0,rbytes);

        SAL_aeadEncrypt(&session->K_send,5,&session->IO.val[0],reclen-taglen,&session->IO.val[5],&TAG);
        incrementCryptoContext(&session->K_send);  // increment IV
        OCT_append_octad(&session->IO,&TAG);
    }
    if (flush)
        sendFlushIO(session);
}

// build and transmit unencrypted client hello. Append pre-prepared extensions
void sendClientHello(TLS_session *session,int version,octad *CH,octad *CRN,bool already_agreed,octad *EXTENSIONS,int extra,bool resume,bool flush)
{
    //char rn[32];
    //octad RN = {0, sizeof(rn), rn};
    char cs[2+TLS_MAX_CIPHER_SUITES*2];
    octad CS = {0, sizeof(cs), cs};
	int nsc;
	int ciphers[TLS_MAX_CIPHER_SUITES];
    int compressionMethods=0x0100;
    int total=8;
    int extlen=EXTENSIONS->len+extra;

	nsc=SAL_ciphers(ciphers);  
	if (already_agreed)
	{ // cipher suite already agreed
		nsc=1;
		ciphers[0]=session->cipher_suite;
	}

    total+=32; // Random bytes clientRandom(&RN);
	total+=33;
    if (!resume) { // if its a handshake resumption, re-use the old id?? Since its the same session?
        for (int i=0;i<32;i++)
			session->id[i]=SAL_randomByte();
	}
 
    total+=cipherSuites(&CS,nsc,ciphers);

    OCT_kill(CH);
    OCT_append_byte(CH,CLIENT_HELLO,1);  // clientHello handshake message  // 1
    OCT_append_int(CH,total+extlen-2,3);   // 3

    OCT_append_int(CH,TLS1_2,2);           // 2
    OCT_append_octad(CH,CRN);              // 32
    OCT_append_byte(CH,32,1);        // 1   
    OCT_append_bytes(CH,session->id,32);              // 32
    OCT_append_octad(CH,&CS);              // 2+TLS_MAX_CIPHER_SUITES*2
    OCT_append_int(CH,compressionMethods,2);  // 2

    OCT_append_int(CH,extlen,2);              // 2

// transmit it
    sendClientMessage(session,HSHAKE,version,CH,EXTENSIONS,flush);
}

// Send "binder",
void sendBinder(TLS_session *session,octad *BND,bool flush)
{
    char b[TLS_MAX_HASH+3];
    octad B={0,sizeof(b),b};
    int tlen2=BND->len+1;
    //OCT_kill(B);
    OCT_append_int(&B,tlen2,2);
    OCT_append_int(&B,BND->len,1);
    OCT_append_octad(&B,BND);
    runningHash(session,&B);
    sendClientMessage(session,HSHAKE,TLS1_2,&B,NULL,flush);
}

// send client alert - might be encrypted if send!=NULL
void sendAlert(TLS_session *session,int type)
{
    char pt[2];
    octad PT={0,sizeof(pt),pt};
    //char buff[48];
    //octad BUFF={0,sizeof(buff),buff};
    OCT_append_byte(&PT,0x02,1);  // alerts are always fatal
    OCT_append_byte(&PT,type,1);  // alert type
    OCT_kill(&session->IO); session->ptr=0;
    sendClientMessage(session,ALERT,TLS1_2,&PT,NULL,true);
    log(IO_PROTOCOL,(char *)"Alert sent to Server - ",NULL,0,NULL);
    logAlert(type);
    session->status=TLS13_DISCONNECTED; // write side of connection is now off
}

void sendKeyUpdate(TLS_session *session,int type)
{
	char up[5];
	octad UP={0,sizeof(up),up};
	OCT_append_byte(&UP,KEY_UPDATE,1);
	OCT_append_int(&UP,1,3);
	OCT_append_int(&UP,type,1);
	OCT_kill(&session->IO); session->ptr=0;
	sendClientMessage(session,HSHAKE,TLS1_2,&UP,NULL,true); // sent using old keys
	deriveUpdatedKeys(&session->K_send,&session->STS); // now update keys
    log(IO_PROTOCOL,(char *)"KEY UPDATE REQUESTED\n",NULL,0,NULL);
}

// Send final client handshake verification data
void sendClientFinish(TLS_session *session,octad *CHF)
{
    char pt[4];
    octad PT={0,sizeof(pt),pt};

    OCT_append_byte(&PT,FINISHED,1);  // indicates handshake message "client finished" 
    OCT_append_int(&PT,CHF->len,3); // .. and its length 

    runningHash(session,&PT);
    runningHash(session,CHF);
    sendClientMessage(session,HSHAKE,TLS1_2,&PT,CHF,true);
}

/* Send Client Cert Verify */
void sendClientCertVerify(TLS_session *session, int sigAlg, octad *CCVSIG)
{
    char pt[10];
    octad PT={0,sizeof(pt),pt};
    OCT_append_byte(&PT,CERT_VERIFY,1);
    OCT_append_int(&PT,4+CCVSIG->len,3);
    OCT_append_int(&PT,sigAlg,2);
    OCT_append_int(&PT,CCVSIG->len,2);
    runningHash(session,&PT);
    runningHash(session,CCVSIG);
    sendClientMessage(session,HSHAKE,TLS1_2,&PT,CCVSIG,true);
}

// Send Client Certificate 
void sendClientCertificateChain(TLS_session *session,octad *CERTCHAIN)
{
    char pt[10];
    octad PT={0,sizeof(pt),pt};

    OCT_append_byte(&PT,CERTIFICATE,1);
    if (CERTCHAIN==NULL) {  // no acceptable certificate available
        OCT_append_int(&PT,4,3);
        OCT_append_byte(&PT,0,1); // cert context
        OCT_append_int(&PT,0,3);  // zero length
        runningHash(session,&PT);
        sendClientMessage(session,HSHAKE,TLS1_2,&PT,NULL,true);
    } else {
        OCT_append_int(&PT,4+CERTCHAIN->len,3);
        OCT_append_byte(&PT,0,1); // cert context
        OCT_append_int(&PT,CERTCHAIN->len,3);  // length of certificate chain
        runningHash(session,&PT);
        runningHash(session,CERTCHAIN);
        if (CERTCHAIN->len>4000)
        { // Break up exceptionally big record that can arise for PQ certs
            octad FIRST={2048,2048,&CERTCHAIN->val[0]};
            octad SECOND={CERTCHAIN->len-2048,CERTCHAIN->max-2048,&CERTCHAIN->val[2048]};
            sendClientMessage(session,HSHAKE,TLS1_2,&PT,&FIRST,true);
            sendClientMessage(session,HSHAKE,TLS1_2,&SECOND,NULL,true);
        } else {
            sendClientMessage(session,HSHAKE,TLS1_2,&PT,CERTCHAIN,true);
        }
    }
} 

// if early data was accepted, send this to indicate early data is finished
void sendEndOfEarlyData(TLS_session *session)
{
    char ed[4];
    octad ED={0,sizeof(ed),ed};
    OCT_append_byte(&ED,END_OF_EARLY_DATA,1);
    OCT_append_int(&ED,0,3);
    runningHash(session,&ED);
    sendClientMessage(session,HSHAKE,TLS1_2,&ED,NULL,true);
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
        return BAD_RECORD_MAC;
    case BAD_RECORD:
        return DECODE_ERROR;
    case BAD_TICKET:
        return ILLEGAL_PARAMETER;
    case NOT_EXPECTED:
        return UNSUPPORTED_EXTENSION;
    case CA_NOT_FOUND:
        return UNKNOWN_CA;
    case CERT_OUTOFDATE:
        return CERTIFICATE_EXPIRED;
    case MEM_OVERFLOW:
        return DECODE_ERROR;
	case FORBIDDEN_EXTENSION:
		return ILLEGAL_PARAMETER;
	case MAX_EXCEEDED:
		return RECORD_OVERFLOW;
	case CERT_VERIFY_FAIL:
		return DECRYPT_ERROR;
	case BAD_HANDSHAKE:
		return HANDSHAKE_FAILURE;
	case BAD_REQUEST_UPDATE:
		return ILLEGAL_PARAMETER;
	case BAD_MESSAGE:
	case EMPTY_CERT_CHAIN:
		return DECODE_ERROR;
    default:
        return ILLEGAL_PARAMETER;    
    }
}
