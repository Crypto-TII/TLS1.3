// 
// Process input received from Server
//

#include "tls_client_recv.h"
#include "tls_cert_chain.h"
#include "tls_logger.h"

// First some functions for parsing values out of an octad string
// parse out an octad of length len from octad M into E
// ptr is a moving pointer through the octad M
ret parseoctad(octad *E,int len,octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    if (ptr+len>M->len) return r;   // not enough in M - probably need to read in some more
    if (E==NULL)
    {
        ptr+=len;
    } else {
        E->len=len;
        for (int i=0;i<len && i<E->max;i++ )
            E->val[i]=M->val[ptr++];
    }
    r.val=len; r.err=0;             // it looks OK
    return r;
}

// parse out an octad of length len from octad M
// ptr is a moving pointer through the octad M
// but now E is just a pointer into M
ret parseoctadptr(octad *E,int len,octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    if (ptr+len>M->len) return r;   // not enough in M - probably need to read in some more
    E->len=len;
    E->max=len;
    E->val=&M->val[ptr];
    ptr+=len;
    r.val=len; r.err=0;             // it looks OK
    return r;
}

ret parseInt(octad *M,int len,int &ptr)
{
	ret r={0,BAD_RECORD};
	if (ptr+len>M->len) return r;
	r.val=0;
	for (int i=0;i<len;i++)
		r.val=256*r.val+(unsigned int)(unsigned char)M->val[ptr++];
	r.err=0;
	return r;
}

// ALL Server to Client records arrive via this function
// Basic function for reading in a record, which may be only contain a fragment of a larger message

// get another fragment of server response, in the form of a record. Record type encoded in its header
// output message body to IO
// If record is encrypted, decrypt and authenticate it
// append its contents to the end of IO
// returns record type, ALERT, APPLICATION or HSHAKE (or pseudo type TIMED_OUT)
int getServerFragment(TLS_session *session)
{
    int i,rtn,left,pos,rlen,taglen;
    char rh[5];
    octad RH={0,sizeof(rh),rh};

    char tag[TLS_MAX_TAG_SIZE];
    octad TAG={0,sizeof(tag),tag};

    pos=session->IO.len;               // current end of IO
    rtn=getOctad(session->sockptr,&RH,3);  // Get record Header - should be something like 17 03 03 XX YY

// Need to check RH.val for correctness
//printf("Getting a fragment\n");
    if (rtn<0)
        return TIMED_OUT;
//printf("Getting a fragment 1\n");
    if (RH.val[0]==ALERT)
    {
        left=getInt16(session->sockptr);
        getOctad(session->sockptr,&session->IO,left);
        return ALERT;
    }
//printf("Getting a fragment 2\n");
    if (RH.val[0]==CHANGE_CIPHER)
    { // read it, and ignore it
        char sccs[10];
        //octad SCCS={0,sizeof(sccs),sccs};
        left=getInt16(session->sockptr);
        //OCT_append_octad(&SCCS,&RH);
        //OCT_append_int(&SCCS,left,2);
        getBytes(session->sockptr,sccs/*&SCCS.val[5]*/,left);
        //SCCS.len+=left;
        rtn=getOctad(session->sockptr,&RH,3); // get the next record
		if (rtn<0)
			return TIMED_OUT;
    }

    if (RH.val[0]!=HSHAKE && RH.val[0]!=APPLICATION)
        return WRONG_MESSAGE;

    left=getInt16(session->sockptr);
    OCT_append_int(&RH,left,2);
    if (left+pos>session->IO.max)
    { // this commonly happens with big records of application data from server
		logger(IO_DEBUG,(char *)"Record received of length= ",(char *)"%d",left+pos,NULL);
        return MEM_OVERFLOW;   // record is too big - memory overflow
    }
//printf("Getting a fragment 3\n");
    if (!session->K_recv.active)
    { // not encrypted
		if (left>TLS_MAX_PLAIN_FRAG)
			return MAX_EXCEEDED;
        getBytes(session->sockptr,&session->IO.val[pos],left);  // read in record body
        session->IO.len+=left;
        return HSHAKE;
    }
	taglen=session->K_recv.taglen;
	rlen=left-taglen; // plaintext record length
	if (left>TLS_MAX_CIPHER_FRAG)
		return MAX_EXCEEDED;

//printf("record length= %d\n",rlen);

    getBytes(session->sockptr,&session->IO.val[pos],rlen);  // read in record body

    session->IO.len+=(rlen);    
    getOctad(session->sockptr,&TAG,taglen);        // read in correct TAG

    bool success=SAL_aeadDecrypt(&session->K_recv,RH.len,RH.val,rlen,&session->IO.val[pos],&TAG);
    incrementCryptoContext(&session->K_recv); // update IV
    if (!success)
    {
       return AUTHENTICATION_FAILURE;     // tag is wrong   
    }
// get record ending - encodes real (disguised) record type. Could be an Alert.
    int lb=0;
    lb=session->IO.val[session->IO.len-1]; 
    session->IO.len--; // remove it
    while (lb==0 && session->IO.len>0)
    { // could be zero padding
        lb=session->IO.val[session->IO.len-1];   // need to track back through zero padding for this....
        session->IO.len--; // remove it
    }
	if ((lb==HSHAKE || lb==ALERT) && rlen==0)
		return WRONG_MESSAGE;
    if (lb==HSHAKE)
        return HSHAKE;
    if (lb==APPLICATION)
        return APPLICATION;
    if (lb==ALERT)
    { // Alert record received, delete anything in IO prior to alert, and just return 2-byte alert
        OCT_shift_left(&session->IO,pos);
        return ALERT;
    }
    return BAD_RECORD;
}

// These functions read data from the input buffer, and pull more records from a socket if it has to.
// ALL of these records SHOULD be of type HSHAKE

ret parseIntorPull(TLS_session *session,int len,int &ptr)
{
    ret r=parseInt(&session->IO,len,ptr);
    while (r.err)
    { // not enough bytes in IO - Pull in some more
        int rtn=getServerFragment(session); 
        if (rtn!=HSHAKE) {  // Bad input from server (Authentication failure? Wrong record type?)
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IO.val[1];
            break;
        }
        r=parseInt(&session->IO,len,ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer. Create a copy.
ret parseoctadorPull(TLS_session *session,octad *O,int len,int &ptr)
{
    ret r=parseoctad(O,len,&session->IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(session);
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IO.val[1];
            break;
        }
        r=parseoctad(O,len,&session->IO,ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer, but this time the output octad is a pointer into the IO buffer
ret parseoctadorPullptr(TLS_session *session,octad *O,int len,int &ptr)
{
    ret r=parseoctadptr(O,len,&session->IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(session); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IO.val[1];
            break;
        }
        r=parseoctadptr(O,len,&session->IO,ptr);
    }
    return r;
}

// test for a bad response, log what happened and act accordingly
// Very probably requires sending an alert to the server, and aborting
// If Alert received, log it, and abort
bool badResponse(TLS_session *session,ret r) //Socket *client,crypto *send,ret r)
{
    logServerResponse(r);
	if (r.err != 0)
	{
       logger(IO_PROTOCOL,(char *)"Handshake failed\n",NULL,0,NULL);
	}
    if (r.err<0)
    { // send an alert to the Server, and abort
        sendClientAlert(session,alert_from_cause(r.err));
        return true;
    }
    if (r.err==ALERT)
    { // received an alert from the Server - abort
        logger(IO_PROTOCOL,(char *)"*** Alert received - ",NULL,0,NULL);
        logAlert(r.val);
        return true;
    }
    if (r.err) // some other error, maybe time out
        return true;
    return false;
}

// Function return convention. These functions return a "ret" structure
// if r.err +ve log unexpected event and abort
// if r.err -ve send alert and abort
// if r.err = ALERT, r.val=received alert code
// if all goes well, r.val returns message type, r.err=0

// Note: we are on a hair trigger here. Anything doesn't look right, we bomb out.

// Functions to process server responses
// Deals with any kind of fragmentation
// Build up server handshake response in IO, decrypting each fragment in-place
// extract Encrypted Extensions, Certificate Chain, Server Certificate Signature and Server Verifier Data
// update transcript hash
// Bad actor Server could be throwing anything at us - so be careful

// Extract first byte to determine message type
ret getWhatsNext(TLS_session *session)
{
    int nb,ptr=0;
    ret r;

    r=parseIntorPull(session,1,ptr); 
    if (r.err) return r; 

	nb=r.val;
	if (nb==END_OF_EARLY_DATA || nb==KEY_UPDATE) { // Servers MUST NOT send this.... KEY_UPDATE should not happen at this stage
		r.err=WRONG_MESSAGE;
		return r;
	}
//logger((char *)"IO= \n",NULL,0,IO);

    char b[1];
    b[0]=r.val;
    SAL_hashProcessArray(&session->tlshash,b,1);
    OCT_shift_left(&session->IO,ptr); 
    return r;      
}

// Get encrypted extensions
ret getServerEncryptedExtensions(TLS_session *session,ee_status *enc_ext_expt,ee_status *enc_ext_resp)
{
    ret r;
    int nb,ext,len,tlen,mfl,ptr=0;
    int unexp=0;

    OCT_kill(&session->IO); // clear IO buffer

    r=getWhatsNext(session);
    if (r.err) return r;
    nb=r.val;

    r=parseIntorPull(session,3,ptr); if (r.err) return r;         // message length    

    enc_ext_resp->early_data=false;
    enc_ext_resp->alpn=false;
    enc_ext_resp->server_name=false;
    enc_ext_resp->max_frag_length=false;

    if (nb!=ENCRYPTED_EXTENSIONS) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,2,ptr); len=r.val; if (r.err) return r; // length of extensions

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"
    while (len>0)
    {
        r=parseIntorPull(session,2,ptr); ext=r.val; if (r.err) return r;
        len-=2;
        r=parseIntorPull(session,2,ptr); tlen=r.val; if (r.err) return r;
        len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            if (tlen!=0) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }
            enc_ext_resp->early_data=true;
            if (!enc_ext_expt->early_data) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;
        case MAX_FRAG_LENGTH :
            r=parseIntorPull(session,1,ptr); if (r.err) return r; // ideally this should the same as requested by client
            len-=tlen;                                       // but server may have ignored this request... :( so we ignore this response 
            if (tlen!=1) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }            
            enc_ext_resp->max_frag_length=true;
            if (!enc_ext_expt->max_frag_length) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;

		case RECORD_SIZE_LIMIT:

//	printf("*****RECORD_SIZE_LIMIT EXTENSION RECEIVED*****\n");
			r=parseIntorPull(session,2,ptr); mfl=r.val; if (r.err) return r;
			len-=tlen;
            if (tlen!=2 || mfl<64) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            } 
//	printf("server max record = %d\n",mfl);

			session->server_max_record=mfl;
			break;


        case APP_PROTOCOL :
            r=parseIntorPull(session,2,ptr); mfl=r.val; if (r.err) return r;
            r=parseIntorPull(session,1,ptr); mfl=r.val; if (r.err) return r;
            r=parseoctadorPull(session,NULL,mfl,ptr);  if (r.err) return r; // ALPN code - send to NULL -- assume its the one I asked for
            len-=tlen;
            enc_ext_resp->alpn=true;
            if (!enc_ext_expt->alpn) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;
        case SERVER_NAME:
            enc_ext_resp->server_name=true;
            if (tlen!=0) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }            
            if (!enc_ext_expt->server_name) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;
		case SIG_ALGS:
		case SIG_ALGS_CERT:
		case KEY_SHARE:
		case PSK_MODE:
		case PRESHARED_KEY:
		case TLS_VER:
		case COOKIE:
		case PADDING:
            len-=tlen; ptr+=tlen; // skip over it
            r.err=FORBIDDEN_EXTENSION;
            return r;
        default:    // ignore all other extensions
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash
    SAL_hashProcessArray(&session->tlshash,session->IO.val,ptr);

    OCT_shift_left(&session->IO,ptr);  // Shift octad left - rewind to start 
    if (unexp>0)    
        logger(IO_DEBUG,(char *)"Unrecognized extensions received\n",NULL,0,NULL);
    r.val=nb;
    return r;
}

// Receive a Certificate request
ret getCertificateRequest(TLS_session *session,int &nalgs,int *sigalgs)
{
    ret r;
    int i,nb,ext,len,tlen,ptr=0;
    int unexp=0;

    r=parseIntorPull(session,3,ptr); if (r.err) return r;         // message length 
    r=parseIntorPull(session,1,ptr); nb=r.val; if (r.err) return r;
    if (nb!=0x00) {
        r.err= MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
        return r;
    }
    r=parseIntorPull(session,2,ptr); len=r.val; if (r.err) return r; // length of extensions

    nalgs=0;
// extension must include signature algorithms
    while (len>0)
    {
        r=parseIntorPull(session,2,ptr); ext=r.val; if (r.err) return r;
        len-=2;
        switch (ext)
        {
        case SIG_ALGS :
            r=parseIntorPull(session,2,ptr); tlen=r.val; if (r.err) return r; 
            len-=2;  
            r=parseIntorPull(session,2,ptr); nalgs=r.val/2; if (r.err) return r;
            len-=2;
            for (i=0;i<nalgs;i++)
            {
                r=parseIntorPull(session,2,ptr); if (r.err) return r;
                if (i<TLS_MAX_SUPPORTED_SIGS) sigalgs[i]=r.val;
                len-=2;
            }
            if (tlen!=2+2*nalgs) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }            
            if (nalgs>TLS_MAX_SUPPORTED_SIGS) nalgs=TLS_MAX_SUPPORTED_SIGS;
            break;
        default:    // ignore all other extensions
            r=parseIntorPull(session,2,ptr); tlen=r.val; 
            len-=2;  // length of extension
            //r=parseoctadorPull(session->sockptr,&U,tlen,ptr,recv);   // to look at extension
            //printf("Unexpected Extension= "); OCT_output(&U);
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash
    SAL_hashProcessArray(&session->tlshash,session->IO.val,ptr);
   
    OCT_shift_left(&session->IO,ptr);  // Shift octad left - rewind to start 

    if (nalgs==0) { // must specify at least one signature algorithm
        r.err=UNRECOGNIZED_EXT;
        return r;
    } 
    if (unexp>0)    
        logger(IO_DEBUG,(char *)"Unrecognized extensions received\n",NULL,0,NULL);
    r.val=CERT_REQUEST;
    return r;
}

// Get certificate chain, and check its validity 
ret getCheckServerCertificateChain(TLS_session *session,octad *PUBKEY)
{
    ret r;
    int nb,len,ptr=0;
    octad CERTCHAIN;       // // Clever re-use of memory - share memory rather than make a copy!
    CERTCHAIN.len=0;

    r=parseIntorPull(session,3,ptr); len=r.val; if (r.err) return r;         // message length   
    logger(IO_DEBUG,(char *)"Certificate Chain Length= ",(char *)"%d",len,NULL);

    r=parseIntorPull(session,1,ptr); nb=r.val; if (r.err) return r;
    if (nb!=0x00) {
        r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
        return r;
    }
    r=parseIntorPull(session,3,ptr); len=r.val; if (r.err) return r;    // get length of certificate chain

	if (len==0)
	{
		r.err=EMPTY_CERT_CHAIN;
		return r;
	}

    r=parseoctadorPullptr(session,&CERTCHAIN,len,ptr); if (r.err) return r; // get pointer to certificate chain

// Update Transcript hash
    SAL_hashProcessArray(&session->tlshash,session->IO.val,ptr);

    r.err=checkServerCertChain(&CERTCHAIN,session->hostname,PUBKEY);

    OCT_shift_left(&session->IO,ptr);  // rewind to start
    r.val=CERTIFICATE;

    return r;
}

// Get Server proof that he owns the Certificate, by receiving its signature SCVSIG on transcript hash
ret getServerCertVerify(TLS_session *session,octad *SCVSIG,int &sigalg)
{
    ret r;
    int nb,len,ptr=0;

    r=parseIntorPull(session,3,ptr); if (r.err) return r; // message length    

    OCT_kill(SCVSIG);
    r=parseIntorPull(session,2,ptr); sigalg=r.val; if (r.err) return r; // may for example be 0804 - RSA-PSS-RSAE-SHA256
    r=parseIntorPull(session,2,ptr); len=r.val; if (r.err) return r;    // sig data follows
    r=parseoctadorPull(session,SCVSIG,len,ptr); if (r.err) return r;
   
// Update Transcript hash
    SAL_hashProcessArray(&session->tlshash,session->IO.val,ptr);

    OCT_shift_left(&session->IO,ptr);  // rewind to start
    r.val=CERT_VERIFY;
    return r;
}

// Get handshake finish verifier data in HFIN
ret getServerFinished(TLS_session *session,octad *HFIN)
{
    ret r;
    int nb,len,ptr=0;

    r=getWhatsNext(session); nb=r.val;
    if (r.err) return r;

    if (nb!=FINISHED)
    {        
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,3,ptr); len=r.val; if (r.err) return r;         // message length    

    OCT_kill(HFIN);
    r=parseoctadorPull(session,HFIN,len,ptr); if (r.err) return r;

// Update Transcript hash
    SAL_hashProcessArray(&session->tlshash,session->IO.val,ptr);
   
    OCT_shift_left(&session->IO,ptr);  // rewind to start
    r.val=FINISHED;
    return r;
}

// Handshake Retry Request
static const char *hrrh= (const char *)"CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";

// Process initial serverHello - NOT encrypted
// pskid >=0 if Pre-Shared-Key is accepted
ret getServerHello(TLS_session *session,int &kex,octad *CID,octad *CK,octad *PK,int &pskid)
{
    ret r;
    int i,tls,svr,left,rtn,silen,cmp,extLen,ext,tmplen,pklen,cipher;
    bool retry=false;
    char sid[32];
    octad SID = {0, sizeof(sid), sid};
    char srn[32];
    octad SRN={0,sizeof(srn),srn};    
    char hrr[40];
    octad HRR={0,sizeof(hrr),hrr};

// need this to check for Handshake Retry Request    
    OCT_from_hex(&HRR,(char *)hrrh);

    kex=-1;
	//cipher=-1;
    pskid=-1;


    OCT_kill(CK); OCT_kill(PK);
// get first fragment - not encrypted
    OCT_kill(&session->IO);

// start parsing mandatory components
    int ptr=0;
    r=parseIntorPull(session,1,ptr); if (r.err) return r; // should be Server Hello
    if (r.val!=SERVER_HELLO)
    {
        r.err=BAD_HELLO;
        return r;
    }

    r=parseIntorPull(session,3,ptr); left=r.val; if (r.err) return r;   // If not enough, pull in another fragment
    r=parseIntorPull(session,2,ptr); svr=r.val; if (r.err) return r;
    left-=2;                // whats left in message

    if (svr!=TLS1_2) { 
        r.err=NOT_TLS1_3;  // don't ask
        return r;
    }

    r= parseoctadorPull(session,&SRN,32,ptr); if (r.err) return r;
    left-=32;

    if (OCT_compare(&SRN,&HRR))
    {
        retry=true;        // "random" data was not random at all - indicated Handshake Retry Request!
    }
    r=parseIntorPull(session,1,ptr); silen=r.val; if (r.err || silen!=32) return r; 
    left-=1;
    r=parseoctadorPull(session,&SID,silen,ptr); if (r.err) return r;
    left-=silen;  

// Tricky one. According to the RFC (4.1.3) this check should be made, even though the session id is "legacy",
// Unfortunately it is not made clear if the same session ID should be use on a handshake resumption.
// We note that some servers echo the original id, not a new id associated with a new Client Hello
// Solution here is to use same id on resumption(?)
    if (!OCT_compare(CID,&SID)) { 
        r.err=ID_MISMATCH;  // check identities match
        return r;
    }
    r=parseIntorPull(session,2,ptr); cipher=r.val; if (r.err) return r;
    left-=2;

	if (session->cipher_suite!=0)
	{ // don't allow a change after initial assignment
		if (cipher!=session->cipher_suite)
		{
			r.err=BAD_HELLO;
			return r;
		}
	}
	session->cipher_suite=cipher;

    r=parseIntorPull(session,1,ptr); cmp=r.val; if (r.err) return r;
    left-=1; // Compression not used in TLS1.3
    if (cmp!=0x00) { 
        r.err=NOT_TLS1_3;  // don't ask
        return r;
    }

    r=parseIntorPull(session,2,ptr); extLen=r.val; if (r.err) return r;
    left-=2;  
    if (left!=extLen) { // Check space left is size of extensions
        r.err=BAD_HELLO;
        return r;
    }

// process extensions
    while (extLen>0)
    {
        r=parseIntorPull(session,2,ptr); ext=r.val; if (r.err) return r;
        extLen-=2;
        r=parseIntorPull(session,2,ptr); tmplen=r.val; if (r.err) break;
        extLen-=2;
        extLen-=tmplen;
        switch (ext)
        {
        case KEY_SHARE :
            { // actually mandatory
                r=parseIntorPull(session,2,ptr); kex=r.val; if (r.err) break;
                if (!retry)
                { // its not a retry request
                    r=parseIntorPull(session,2,ptr); pklen=r.val; if (r.err) break;   // FIX this first for HRR
                    r=parseoctadorPull(session,PK,pklen,ptr); 
                }
                break;
            }
        case PRESHARED_KEY :
            { // Indicate acceptance of pre-shared key
                r=parseIntorPull(session,2,ptr); pskid=r.val;
                break;
            }
        case COOKIE :
            { // Pick up a cookie
                r=parseoctadorPull(session,CK,tmplen,ptr);
                break;
            }
        case TLS_VER :
            { // report TLS version
                r=parseIntorPull(session,2,ptr); tls=r.val; if (r.err) break; // get TLS version
                if (tls!=TLS1_3) r.err=NOT_TLS1_3;
                break;
            }
       default :
            r.err=UNRECOGNIZED_EXT;            
            break;           
        }
        if (r.err) return r;
    }

    if (retry)
        r.val=HANDSHAKE_RETRY;
    else
        r.val=SERVER_HELLO;
    return r;
}

