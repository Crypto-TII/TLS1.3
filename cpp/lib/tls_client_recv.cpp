// 
// Process input received from Server
//

#include "tls_client_recv.h"
#include "tls_cert_chain.h"
#include "tls_logger.h"

// check for malformed input
bool malformed(int rval,int maxm) {

    if ((rval&1) == 1) { // if its odd -> error
        return true;
    }
    if (rval/2 > maxm) { // if its too big -> error
        return true;
    }
    return false;
}

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

// parse out an array of bytes of length len
ret parsebytes(char *e,int len,octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    if (ptr+len>M->len) return r;   // not enough in M - probably need to read in some more
    if (e==NULL)
    {
        ptr+=len;
    } else {
        for (int i=0;i<len;i++ )
            e[i]=M->val[ptr++];
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

// parse out an integer of length len
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

// Protocol messages can be fragmented, and arrive as multiple records. 
// Record contents are appended to the input buffer. 
// Messages are read from the input buffer, and on reaching the end of the buffer, 
// new records are pulled in to complete a message. 
// Most records must be decrypted before being appended to the message buffer.

// get another fragment of server response, in the form of a record. Record type encoded in its header
// output message body to IO
// If record is encrypted, decrypt and authenticate it
// append its contents to the end of IO
// returns record type, ALERT, APPLICATION or HSHAKE (or pseudo type TIMED_OUT)
int getServerRecord(TLS_session *session)
{
    int i,rtn,left,pos,rlen,taglen;
    char rh[5];
    octad RH={0,sizeof(rh),rh};

    char tag[TLS_MAX_TAG_SIZE];
    octad TAG={0,sizeof(tag),tag};

    pos=session->IBUFF.len;               // current end of IO
    rtn=getOctad(session->sockptr,&RH,3);  // Get record Header - should be something like 17 03 03 XX YY

// Need to check RH.val for correctness
    if (rtn<0)
        return TIMED_OUT;
    if (RH.val[0]==ALERT)
    {  // plaintext alert
        left=getInt16(session->sockptr);
		if (left!=2) return BAD_RECORD;                     // ** RM
        rtn=getOctad(session->sockptr,&session->IBUFF,left);
        if (rtn<0)
            return TIMED_OUT;
        return ALERT;
    }
    if (RH.val[0]==CHANGE_CIPHER)
    { // read it, and ignore it
        char sccs[10];
        left=getInt16(session->sockptr);
		if (left!=1) return BAD_RECORD;					// ** RM
        rtn=getBytes(session->sockptr,sccs,left);
        if (rtn<0)
            return TIMED_OUT;
		if (session->status!=TLS13_HANDSHAKING)
			return WRONG_MESSAGE;
        rtn=getOctad(session->sockptr,&RH,3); // get the next record and carry on
		if (rtn<0)
			return TIMED_OUT;
    }

    if (RH.val[0]!=HSHAKE && RH.val[0]!=APPLICATION)
        return WRONG_MESSAGE;

    left=getInt16(session->sockptr);
	if (left>TLS_MAX_CIPHER_FRAG)
		return MAX_EXCEEDED;

    OCT_append_int(&RH,left,2);
    if (left+pos>session->IBUFF.max)
    { // this commonly happens with big records of application data from server
		log(IO_DEBUG,(char *)"Record received of length= ",(char *)"%d",left+pos,NULL);
        return MEM_OVERFLOW;   // record is too big - memory overflow
    }
    if (!session->K_recv.active)
    { // not encrypted
		if (RH.val[0]==APPLICATION){
			return BAD_RECORD;
		}
		if (left>TLS_MAX_PLAIN_FRAG)
			return MAX_EXCEEDED;
		if (left==0)
			return WRONG_MESSAGE;
        rtn=getBytes(session->sockptr,&session->IBUFF.val[pos],left);  // read in record body
        if (rtn<0)
            return TIMED_OUT;
        session->IBUFF.len+=left;
        return HSHAKE;
    }
	if (RH.val[0]==HSHAKE) {
		return BAD_RECORD;
	}
	taglen=session->K_recv.taglen;
	if (left < taglen) 
		return BAD_RECORD;
  
	rlen=left-taglen; // plaintext record length

    rtn=getBytes(session->sockptr,&session->IBUFF.val[pos],rlen);  // read in record body
    if (rtn<0)
        return TIMED_OUT;

    session->IBUFF.len+=(rlen);    // place record into iobuff
    rtn=getOctad(session->sockptr,&TAG,taglen);        // extract TAG
    if (rtn<0)
        return TIMED_OUT;
    bool success=SAL_aeadDecrypt(&session->K_recv,RH.len,RH.val,rlen,&session->IBUFF.val[pos],&TAG);
    if (!success)
       return AUTHENTICATION_FAILURE;     // tag is wrong   
    
    incrementCryptoContext(&session->K_recv); // update IV

// get record ending - encodes real (disguised) record type. Could be an Alert.
    int lb=session->IBUFF.val[session->IBUFF.len-1]; 
    session->IBUFF.len--; rlen--; // remove it
    while (lb==0 && rlen>0 /*session->IBUFF.len>0*/)
    { // could be zero padding
        lb=session->IBUFF.val[session->IBUFF.len-1];   // need to track back through zero padding for this....
        session->IBUFF.len--; rlen--;// remove it
    }

	if (rlen>TLS_MAX_PLAIN_FRAG) return MAX_EXCEEDED;

	// rlen is Inner Plaintext length?
	if ((lb==HSHAKE || lb==ALERT) && rlen==0)
		return WRONG_MESSAGE;  // Implementations MUST NOT send zero-length fragments of Handshake types
    if (lb==HSHAKE)
        return HSHAKE;
    if (lb==APPLICATION)
        return APPLICATION;
    if (lb==ALERT)
    { // Disguised Alert record received, delete anything in IO prior to alert, and just return 2-byte alert
        OCT_shift_left(&session->IBUFF,pos);
        return ALERT;
    }
    return WRONG_MESSAGE;
}

// These functions read data from the input buffer, and pull more handshake records from a socket if it has to.
// ALL of these records SHOULD be of type HSHAKE
ret parseIntorPull(TLS_session *session,int len)
{
    ret r=parseInt(&session->IBUFF,len,session->ptr);
    while (r.err)
    { // not enough bytes in IO - Pull in some more
        int rtn=getServerRecord(session); 
        if (rtn!=HSHAKE) {  // Bad input from server (Authentication failure? Wrong record type?)
            r.err=rtn;  // probably negative error
            if (rtn==ALERT) r.val=session->IBUFF.val[1];
			if (rtn==APPLICATION) r.err=WRONG_MESSAGE;
            break;
        }
        r=parseInt(&session->IBUFF,len,session->ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer. Create a copy.
ret parseoctadorPull(TLS_session *session,octad *O,int len)
{
    ret r=parseoctad(O,len,&session->IBUFF,session->ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerRecord(session);
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IBUFF.val[1];
			if (rtn==APPLICATION) r.err=WRONG_MESSAGE;
            break;
        }
        r=parseoctad(O,len,&session->IBUFF,session->ptr);
    }
    return r;
}

// Get byte array o of length len from the IO buffer. Create a copy.
ret parsebytesorPull(TLS_session *session,char *o,int len)
{
    ret r=parsebytes(o,len,&session->IBUFF,session->ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerRecord(session);
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IBUFF.val[1];
			if (rtn==APPLICATION) r.err=WRONG_MESSAGE;
            break;
        }
        r=parsebytes(o,len,&session->IBUFF,session->ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer, but this time the output octad is a pointer into the IO buffer
ret parseoctadorPullptrX(TLS_session *session,octad *O,int len)
{
    ret r=parseoctadptr(O,len,&session->IBUFF,session->ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerRecord(session); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=session->IBUFF.val[1];
			if (rtn==APPLICATION) r.err=WRONG_MESSAGE;
            break;
        }
        r=parseoctadptr(O,len,&session->IBUFF,session->ptr);
    }
    return r;
}

// Could have (a) received an alert, or (b) had problem with response, so need to send an alert
// test for a bad response, log what happened and act accordingly
// Very probably requires sending an alert to the server, and aborting
// If Alert received, log it, send alert, abort
bool badResponse(TLS_session *session,ret r) //Socket *client,crypto *send,ret r)
{
    logServerResponse(r);
	if (r.err != 0)
	{
       log(IO_PROTOCOL,(char *)"Handshake failed\n",NULL,0,NULL);
	}
    if (r.err<0)
    { // send an alert to the Server, and abort
        sendAlert(session,alert_from_cause(r.err));
        return true;
    }
    if (r.err==ALERT)
    { // received an alert from the Server - abort
        log(IO_PROTOCOL,(char *)"*** Alert received - ",NULL,0,NULL);
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
ret seeWhatsNext(TLS_session *session)
{
    int nb;//,ptr=0;
    ret r;

    //session->ptr=0;
    r=parseIntorPull(session,1); 
    if (r.err) return r; 
    session->ptr-=1;

	nb=r.val;
	if (nb==END_OF_EARLY_DATA || nb==KEY_UPDATE) { // Servers MUST NOT send this.... KEY_UPDATE should not happen at this stage
		r.err=WRONG_MESSAGE;
		return r;
	}
    return r;      
}

// Get encrypted extensions
ret getServerEncryptedExtensions(TLS_session *session,ee_status *enc_ext_expt,ee_status *enc_ext_resp)
{
    ret r;
    int nb,left,ext,len,tlen,xlen,mfl,cct,sct;//,ptr=0;
    int unexp=0;

    r=parseIntorPull(session,1);
    if (r.err) return r;
    nb=r.val;

    if (nb!=ENCRYPTED_EXTENSIONS) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,3); left=r.val; if (r.err) return r;         // message length    

    enc_ext_resp->early_data=false;
    enc_ext_resp->alpn=false;
    enc_ext_resp->server_name=false;
    enc_ext_resp->max_frag_length=false;

    r=parseIntorPull(session,2); len=r.val; if (r.err) return r; // length of extensions


    if (left!=len+2) {
        r.err=BAD_MESSAGE;
        return r;
    }

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"
    while (len>0)
    {
        r=parseIntorPull(session,2); ext=r.val; if (r.err) return r;
        r=parseIntorPull(session,2); tlen=r.val; if (r.err) return r;
		if (len<tlen+4) {
            r.err=BAD_MESSAGE;
            return r;
        }
		len-=(tlen+4);
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
            r=parseIntorPull(session,1); mfl=r.val; if (r.err) return r; // ideally this should the same as requested by client
                                                   // but server may have ignored this request... :( so we ignore this response 
            if (mfl!=TLS_MAX_FRAG || tlen!=1) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }     
            enc_ext_resp->max_frag_length=true;
            if (!enc_ext_expt->max_frag_length) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;

		case CLIENT_CERT_TYPE :
			r=parseIntorPull(session,1); cct=r.val; if (r.err) return r;
		    if (tlen!=1) {
				r.err=UNRECOGNIZED_EXT;
                return r;
		    }
#ifdef PREFER_RAW_CLIENT_PUBLIC_KEY
			if (cct!=RAW_PUBLIC_KEY) {
				session->client_cert_type=X509_CERT;
			} else {
				session->client_cert_type=RAW_PUBLIC_KEY;
			}
#else
			session->client_cert_type=X509_CERT;
#endif
		    break;
		case SERVER_CERT_TYPE :
			r=parseIntorPull(session,1); sct=r.val; if (r.err) return r;
		    if (tlen!=1) {
				r.err=UNRECOGNIZED_EXT;
                return r;
		    }
#ifdef PREFER_RAW_SERVER_PUBLIC_KEY
			if (sct!=RAW_PUBLIC_KEY) {
				session->server_cert_type=X509_CERT;
			} else {
				session->server_cert_type=RAW_PUBLIC_KEY;
			}
#else
			 session->server_cert_type=X509_CERT;
#endif
		     break;
		case RECORD_SIZE_LIMIT:
			r=parseIntorPull(session,2); mfl=r.val; if (r.err) return r;
			
            if (tlen!=2 || mfl<64) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            } 
			session->max_record=mfl;
			break;

        case APP_PROTOCOL :
            r=parseIntorPull(session,2); xlen=r.val; if (r.err) return r;
            r=parseIntorPull(session,1); mfl=r.val; if (r.err) return r;
			if (tlen!=xlen+2 || xlen!=mfl+1)										// ** RM
			{
                r.err=UNRECOGNIZED_EXT;
                return r;
			}
            r=parseoctadorPull(session,NULL,mfl);  if (r.err) return r; // ALPN code - send to NULL -- assume its the one I asked for
            
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
            session->ptr+=tlen; // skip over it
            r.err=FORBIDDEN_EXTENSION;
            return r;
        default:    // ignore all other extensions
            session->ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash and rewind IO buffer
    runningHashIOrewind(session);

    if (unexp>0)    
    {
        r.err=UNRECOGNIZED_EXT;
        log(IO_DEBUG,(char *)"Unrecognized extensions received\n",NULL,0,NULL);
    }
    r.val=nb;
    return r;
}

// check for overlap given server signature capabilities, and my client certificate
static bool overlap(int *serverSigAlgs,int nssa,int *serverCertSigAlgs,int nscsa) {
    int clientCertReqs[TLS_MAX_SUPPORTED_SIGS];
    int nsreq=getSigRequirements(clientCertReqs);
    for (int i=0;i<nsreq;i++) {
        bool itsthere=false;
        int sig=clientCertReqs[i];
        for (int j=0;j<nssa;j++) {
            if (sig==serverSigAlgs[j]) {
                itsthere=true;
            }
        }
        for (int j=0;j<nscsa;j++) {
            if (sig==serverCertSigAlgs[j]) {
                itsthere=true;
            }
        }
        if (!itsthere) {
            return false;
        }
    }
    return true;    
}

// Receive a Certificate request
ret getCertificateRequest(TLS_session *session,bool context)
{
    ret r;
    int i,left,nb,ext,len,tlen,nssa,nscsa;//,ptr=0;
    int unexp=0;
    int sigalgs[TLS_MAX_SUPPORTED_SIGS]; // acceptable client signature types
    int certsigalgs[TLS_MAX_SUPPORTED_SIGS];

    r=parseIntorPull(session,1); // get message type
    if (r.err!=0) {return r;}
    nb=r.val;
    if (nb != CERT_REQUEST) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,3); left=r.val; if (r.err) return r;         // message length 
    r=parseIntorPull(session,1); nb=r.val; if (r.err) return r;
    if (context)
    {
        if (nb==0x00) {
            r.err= MISSING_REQUEST_CONTEXT;// expecting Request context
            return r;
        }   
		r=parseoctadorPull(session,&session->CTX,nb); if (r.err) return r;
    } else {
        if (nb!=0x00) {
            r.err= MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
            return r;
        }         
    }
    r=parseIntorPull(session,2); len=r.val; if (r.err) return r; // length of extensions

    if (left!=len+3) {
        r.err=BAD_MESSAGE;
        return r;
    }
  
    nssa=nscsa=0;
// extension must include signature algorithms
    while (len>0)
    {
        r=parseIntorPull(session,2); ext=r.val; if (r.err) return r;
        r=parseIntorPull(session,2); tlen=r.val; if (r.err) return r; 
		if (len<tlen+4) {
            r.err=BAD_MESSAGE;
            return r;
        }
        len-=(4+tlen);  
        switch (ext)
        {
        case SIG_ALGS :
            r=parseIntorPull(session,2);  if (r.err) return r;
            if (malformed(r.val,TLS_MAX_SUPPORTED_SIGS) || tlen!=2+r.val) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }
            nssa=r.val/2;
            for (i=0;i<nssa;i++)
            {
                r=parseIntorPull(session,2); if (r.err) return r;
                sigalgs[i]=r.val;
            }
            break;

        case SIG_ALGS_CERT :
            r=parseIntorPull(session,2);  if (r.err) return r;
            if (malformed(r.val,TLS_MAX_SUPPORTED_SIGS) || tlen!=2+r.val) {
                r.err=UNRECOGNIZED_EXT;
                return r;
            }
            nscsa=r.val/2;
            for (i=0;i<nscsa;i++)
            {
                r=parseIntorPull(session,2); if (r.err) return r;
                if (i<TLS_MAX_SUPPORTED_SIGS) certsigalgs[i]=r.val;
            }
            break;

        default:    // ignore all other extensions
            session->ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash and rewind IO buffer
    runningHashIOrewind(session);

    if (nssa==0) { // must specify at least one signature algorithm
        r.err=MISSING_EXTENSIONS;
        return r;
    } 

    if (!overlap(sigalgs,nssa,certsigalgs,nscsa)) {
        log(IO_DEBUG,(char *)"Server cannot verify client certificate\n",NULL,0,NULL);
        r.err=BAD_HANDSHAKE;
        return r;
    }
    if (unexp>0)    
        log(IO_DEBUG,(char *)"Unrecognized extensions received\n",NULL,0,NULL);
    r.val=CERT_REQUEST;
    return r;
}

// Get certificate chain, and check its validity 
ret getCheckServerCertificateChain(TLS_session *session,octad *PUBKEY,octad *SIG)
{
    ret r;
    int nb,len,tlen;
    octad CERTCHAIN;       // // Clever re-use of memory - share memory rather than make a copy!
    CERTCHAIN.len=0;

    r=parseIntorPull(session,1); // get message type
    if (r.err!=0) {return r;}
    nb=r.val;
    if (nb != CERTIFICATE) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,3); len=r.val; if (r.err) return r;         // message length   
    log(IO_DEBUG,(char *)"Certificate Chain Length= ",(char *)"%d",len,NULL);

    if (len==0)
    {
        r.err=EMPTY_CERT_CHAIN;
        return r;
    }

    r=parseIntorPull(session,1); nb=r.val; if (r.err) return r;
    if (nb!=0x00) {
        r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
        return r;
    }
    r=parseIntorPull(session,3); tlen=r.val; if (r.err) return r;    // get length of certificate chain list

	if (tlen==0)
	{
		r.err=EMPTY_CERT_CHAIN;
		return r;
	}
	if (tlen+4!=len)
	{
		r.err=BAD_CERT_CHAIN;
		return r;
	}

    r=parseoctadorPullptrX(session,&CERTCHAIN,tlen); if (r.err) return r; // get pointer to certificate chain

// Update Transcript hash and rewind IO buffer
    runningHashIO(session);     // Got to do this here, as checkServerCertChain may modify IO buffer contents
    r.err=checkServerCertChain(&CERTCHAIN,session->hostname,session->server_cert_type,PUBKEY,SIG);

#ifdef NO_CERT_CHECKS
	r.err=0;
#endif

    rewindIO(session); // now save to rewind

    r.val=CERTIFICATE;
    return r;
}

// Get Server proof that he owns the Certificate, by receiving its signature SCVSIG on transcript hash
ret getServerCertVerify(TLS_session *session,octad *SCVSIG,int &sigalg)
{
    ret r;
    int nb,left,len;//,ptr=0;
	int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
	int nsa=SAL_sigs(sigAlgs);
    r=parseIntorPull(session,1); // get message type
    if (r.err!=0) {return r;}
    nb=r.val;
    if (nb != CERT_VERIFY) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseIntorPull(session,3); left=r.val; if (r.err) return r; // message length    
    OCT_kill(SCVSIG);
    r=parseIntorPull(session,2); sigalg=r.val; if (r.err) return r; // may for example be 0804 - RSA-PSS-RSAE-SHA256

	bool offered=false;
	for (int i=0;i<nsa;i++)
		if (sigalg==sigAlgs[i]) offered=true;
	if (!offered)
	{
		r.err=CERT_VERIFY_FAIL;
		return r;
	}

    r=parseIntorPull(session,2); len=r.val; if (r.err) return r;    // sig data follows
    r=parseoctadorPull(session,SCVSIG,len); if (r.err) return r;

    if (left!=len+4) {
        r.err=BAD_MESSAGE;
        return r;
    }

// Update Transcript hash and rewind IO buffer
    runningHashIOrewind(session);

    r.val=CERT_VERIFY;
    return r;
}

// Get handshake finish verifier data in HFIN
ret getServerFinished(TLS_session *session,octad *HFIN)
{
    ret r;
    int nb,len;
    r=parseIntorPull(session,1); // get message type
    if (r.err!=0) {return r;}
    nb=r.val;
    if (nb != FINISHED) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    int hashtype=SAL_hashType(session->cipher_suite);
    int hlen=SAL_hashLen(hashtype);
    r=parseIntorPull(session,3); len=r.val; if (r.err) return r;         // message length    
    OCT_kill(HFIN);
    r=parseoctadorPull(session,HFIN,hlen); if (r.err) return r;

    if (len!=hlen)
        r.err=BAD_MESSAGE;

// Update Transcript hash and rewind IO buffer
    runningHashIOrewind(session);

    r.val=FINISHED;
    return r;
}

// Handshake Retry Request
static const char *hrrh= (const char *)"CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";

// Process initial serverHello - NOT encrypted
// pskid >=0 if Pre-Shared-Key is accepted
ret getServerHello(TLS_session *session,int &kex,octad *CK,octad *PK,int &pskid)
{
    ret r;
    int i,tls,svr,left,rtn,silen,cmp,extLen,ext,tmplen,pklen,cipher;
    bool retry=false;
    char sid[32];
    char srn[32];
    octad SRN={0,sizeof(srn),srn};    
    char hrr[40];
    octad HRR={0,sizeof(hrr),hrr};

// need this to check for Handshake Retry Request    
    OCT_from_hex(&HRR,(char *)hrrh);

    kex=-1;
    pskid=-1;

    OCT_kill(CK); OCT_kill(PK);
// get first fragment - not encrypted
    OCT_kill(&session->IBUFF);

// start parsing mandatory components
    session->ptr=0;

    r=parseIntorPull(session,1); 
    if (r.err) return r; // should be Server Hello
    if (r.val!=SERVER_HELLO)
    {
        r.err=BAD_HELLO;
        return r;
    }

    r=parseIntorPull(session,3); left=r.val; if (r.err) return r;   // If not enough, pull in another fragment
    r=parseIntorPull(session,2); svr=r.val; if (r.err) return r;

	if (left<72)
	{
		r.err=BAD_HELLO;
		return r;
	}
    left-=2;                // whats left in message

	int legacy_version=svr;
    r= parseoctadorPull(session,&SRN,32); if (r.err) return r;
    left-=32;
    if (OCT_compare(&SRN,&HRR))
    {
        retry=true;        // "random" data was not random at all - indicated Handshake Retry Request!
    }
    r=parseIntorPull(session,1); silen=r.val; if (silen!=32) r.err=BAD_HELLO; if (r.err) return r; 
    left-=1;
    r=parsebytesorPull(session,sid,silen); if (r.err) return r;
    left-=silen;  

// Tricky one. According to the RFC (4.1.3) this check should be made, even though the session id is "legacy",
// Unfortunately it is not made clear if the same session ID should be use on a handshake resumption.
// We note that some servers echo the original id, not a new id associated with a new Client Hello
// Solution here is to use same id on resumption(?)
	bool mismatch=false;
	for (int i=0;i<32;i++)
	{
		if (session->id[i]!=sid[i])
			mismatch=true;
	}
    if (mismatch) { 
        r.err=ID_MISMATCH;  // check identities match
        return r;
    }
    r=parseIntorPull(session,2); cipher=r.val; if (r.err) return r;
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

    r=parseIntorPull(session,1); cmp=r.val; if (r.err) return r;
    left-=1; // Compression not used in TLS1.3
    if (cmp!=0x00) { 
        r.err=NOT_TLS1_3;  // don't ask
        return r;
    }

    r=parseIntorPull(session,2); extLen=r.val; if (r.err) return r;
    left-=2;  
    if (left!=extLen) { // Check space left is size of extensions
        r.err=BAD_HELLO;
        return r;
    }

	int supported_version=0;
// process extensions
    while (extLen>0)
    {
        r=parseIntorPull(session,2); ext=r.val; if (r.err) return r;
        r=parseIntorPull(session,2); tmplen=r.val; if (r.err) break;
		if (extLen<4+tmplen)
		{
			r.err=BAD_HELLO;
			return r;
		}
		extLen-=(4+tmplen);
        switch (ext)
        {
        case KEY_SHARE :
            { // actually mandatory
				int glen=2;
                r=parseIntorPull(session,2); kex=r.val; if (r.err) break;
                if (!retry)
                { // its not a retry request
                    r=parseIntorPull(session,2); pklen=r.val; if (r.err) break;   // FIX this first for HRR
                    r=parseoctadorPull(session,PK,pklen); 
					glen+=(2+pklen);
                }
				if (tmplen!=glen)	
				{
					r.err=BAD_HELLO;
					return r;
				}
                break;
            }
        case PRESHARED_KEY :
            { // Indicate acceptance of pre-shared key
				if (tmplen!=2)	
				{
					r.err=BAD_HELLO;
					return r;
				}
                r=parseIntorPull(session,2); pskid=r.val;
                break;
            }
        case COOKIE :
            { // Pick up a cookie
                r=parseoctadorPull(session,CK,tmplen);
                break;
            }
        case TLS_VER :
            { // report TLS version
				if (tmplen!=2)		
				{
					r.err=BAD_HELLO;
					return r;
				}
                r=parseIntorPull(session,2); tls=r.val; if (r.err) break; // get TLS version
				supported_version=tls;
                break;
            }
       default :
            r.err=UNRECOGNIZED_EXT;            
            break;           
        }
        if (r.err) return r;
    }
    
	if (supported_version==0 || supported_version!=TLS1_3)
		r.err=NOT_TLS1_3;

    if (retry)
        r.val=HANDSHAKE_RETRY;
    else
        r.val=SERVER_HELLO;
    return r;
}

