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

// parse out a 16-bit integer from octad M
ret parseInt16(octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    int b0,b1;
    if (ptr+2>M->len) return r;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    r.val= 256*b0+b1; r.err=0;
    return r;
}

// parse out a 24-bit integer from octad M
ret parseInt24(octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    int b0,b1,b2;
    if (ptr+3>M->len) return r;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    b2=(int)(unsigned char)M->val[ptr++];
    r.val=65536*b0+256*b1+b2; r.err=0;
    return r;
}

// parse out an unsigned 32-bit integer from octad M
ret parseInt32(octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    unsigned int b0,b1,b2,b3;
    if (ptr+4>M->len) return r;
    b0=(unsigned int)(unsigned char)M->val[ptr++];
    b1=(unsigned int)(unsigned char)M->val[ptr++];
    b2=(unsigned int)(unsigned char)M->val[ptr++];
    b3=(unsigned int)(unsigned char)M->val[ptr++];
    r.val=16777216*b0+65536*b1+256*b2+b3; r.err=0;
    return r;
}

// parse out a byte from octad M
ret parseByte(octad *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    if (ptr+1>M->len) 
    {
//        printf("ptr= %d M->len= %d\n",ptr,M->len);
        return r;
    }
    r.val=(unsigned int)(unsigned char)M->val[ptr++]; r.err=0;
    return r;
}

// ALL Server to Client records arrive via this function
// Basic function for reading in a record, which may be only contain a fragment of a larger message

// get another fragment of server response, in the form of a record. Record type encoded in its header
// output message body to IO
// If record is encrypted, decrypt and authenticate it
// append its contents to the end of IO
// returns record type, ALERT, APPLICATION or HSHAKE (or pseudo type TIMED_OUT)
int getServerFragment(Socket &client,crypto *recv,octad *IO)
{
    int i,rtn,left,pos;
    char rh[5];
    octad RH={0,sizeof(rh),rh};

    char tag[TLS_TAG_SIZE];
    octad TAG={0,sizeof(tag),tag};

    pos=IO->len;               // current end of IO
    rtn=getOctad(client,&RH,3);  // Get record Header - should be something like 17 03 03 XX YY

// Need to check RH.val for correctness

    if (rtn<0)
        return TIMED_OUT;
    if (RH.val[0]==ALERT)
    {
        left=getInt16(client);
        getOctad(client,IO,left);
        return ALERT;
    }
    if (RH.val[0]==CHANGE_CIPHER)
    { // read it, and ignore it
        char sccs[10];
        octad SCCS={0,sizeof(sccs),sccs};
        left=getInt16(client);
        OCT_append_octad(&SCCS,&RH);
        OCT_append_int(&SCCS,left,2);
        getBytes(client,&SCCS.val[5],left);
        SCCS.len+=left;
        rtn=getOctad(client,&RH,3); // get the next record
    }

    if (RH.val[0]!=HSHAKE && RH.val[0]!=APPLICATION)
        return BAD_RECORD;

    left=getInt16(client);
    OCT_append_int(&RH,left,2);
    if (left+pos>IO->max)
    { // this commonly happens with big records of application data from server
        return MEM_OVERFLOW;   // record is too big - memory overflow
    }
    if (recv==NULL)
    { // not encrypted
        getBytes(client,&IO->val[pos],left);  // read in record body
        IO->len+=left;
        return HSHAKE;
    }

    getBytes(client,&IO->val[pos],left-16);  // read in record body

    IO->len+=(left-16);    
    getOctad(client,&TAG,16);        // read in correct TAG

    rtn=SAL_aeadDecrypt(recv,RH.len,RH.val,left-16,&IO->val[pos],&TAG);
    incrementCryptoContext(recv); // update IV
    if (rtn<0)
       return AUTHENTICATION_FAILURE;     // tag is wrong   

// get record ending - encodes real (disguised) record type. Could be an Alert.
    int lb=0;
    int pad=0;
    lb=IO->val[IO->len-1]; 
    IO->len--; // remove it
    while (lb==0 && IO->len>0)
    { // could be zero padding
        lb=IO->val[IO->len-1];   // need to track back through zero padding for this....
        IO->len--; // remove it
        pad++;
    }
    if (lb==HSHAKE)
        return HSHAKE;
    if (lb==APPLICATION)
        return APPLICATION;
    if (lb==ALERT)
    { // Alert record received, delete anything in IO prior to alert, and just return 2-byte alert
        OCT_shift_left(IO,pos);
        return ALERT;
    }
    return BAD_RECORD;
}

// These functions read data from the input buffer, and pull more records from a socket if it has to.
// ALL of these records SHOULD be of type HSHAKE

// Get a byte
ret parseByteorPull(Socket &client,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseByte(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - Pull in some more
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn!=HSHAKE) {  // Bad input from server (Authentication failure? Wrong record type?)
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseByte(IO,ptr);
    }
    return r;
}

// Get a 32-bit Int
ret parseInt32orPull(Socket &client,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseInt32(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseInt32(IO,ptr);
    }
    return r;
}

// Get a 24-bit Int
ret parseInt24orPull(Socket &client,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseInt24(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseInt24(IO,ptr);
    }
    return r;
}

// Get a 16-bit Int
ret parseInt16orPull(Socket &client,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseInt16(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseInt16(IO,ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer. Create a copy.
ret parseoctadorPull(Socket &client,octad *O,int len,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseoctad(O,len,IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO);
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseoctad(O,len,IO,ptr);
    }
    return r;
}

// Get an octad O of length len from the IO buffer, but this time the output octad is a pointer into the IO buffer
ret parseoctadorPullptr(Socket &client,octad *O,int len,octad *IO,int &ptr,crypto *recv)
{
    ret r=parseoctadptr(O,len,IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn!=HSHAKE) {
            r.err=rtn;
            if (rtn==ALERT) r.val=IO->val[1];
            break;
        }
        r=parseoctadptr(O,len,IO,ptr);
    }
    return r;
}

// test for a bad response, log what happened and act accordingly
// Very probably requires sending an alert to the server, and aborting
bool badResponse(Socket &client,crypto *send,ret r)
{
    logServerResponse(r);
    if (r.err<0)
    { // send an alert to the Server, and abort
        sendClientAlert(client,alert_from_cause(r.err),send);
        return true;
    }
    if (r.err==ALERT)
    { // received an alert from the Server - abort
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"*** Alert received - ",NULL,0,NULL);
#endif
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
ret getWhatsNext(Socket &client,octad *IO,crypto *recv,unihash *trans_hash)
{
    int ptr=0;
    ret r;

    r=parseByteorPull(client,IO,ptr,recv); 
    if (r.err) return r; 

    char b[1];
    b[0]=r.val;
    SAL_hashProcessArray(trans_hash,b,1);
    OCT_shift_left(IO,ptr); 
    return r;      
}

// Get encrypted extensions
ret getServerEncryptedExtensions(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,ee_expt *enc_ext_expt,ee_resp *enc_ext_resp)
{
    ret r;
    int nb,ext,len,tlen,mfl,ptr=0;
    int unexp=0;
    r=getWhatsNext(client,IO,recv,trans_hash); 
    if (r.err) return r;
    nb=r.val;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;         // message length    

    enc_ext_resp->early_data=false;
    enc_ext_resp->alpn=false;
    enc_ext_resp->server_name=false;
    enc_ext_resp->max_frag_length=false;
    if (nb!=ENCRYPTED_EXTENSIONS) {
        r.err=WRONG_MESSAGE;
        return r;
    }

    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r; // length of extensions

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"
    while (len>0)
    {
        r=parseInt16orPull(client,IO,ptr,recv); ext=r.val; if (r.err) return r;
        len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            r=parseInt16orPull(client,IO,ptr,recv); if (r.err) return r; tlen=r.val;
            len-=2;  // length is zero
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
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r;
            len-=2;
            r=parseByteorPull(client,IO,ptr,recv); mfl=r.val; if (r.err) return r; // ideally this should the same as requested by client
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
        case APP_PROTOCOL :
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r;
            len-=2;  // length of extension
            r=parseInt16orPull(client,IO,ptr,recv); mfl=r.val; if (r.err) return r;
            r=parseByteorPull(client,IO,ptr,recv); mfl=r.val; if (r.err) return r;
            r=parseoctadorPull(client,NULL,mfl,IO,ptr,recv);  if (r.err) return r; // ALPN code - send to NULL
            len-=tlen;
            enc_ext_resp->alpn=true;
            if (!enc_ext_expt->alpn) {
                r.err=NOT_EXPECTED;
                return r;
            }
            break;
        case SERVER_NAME:
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r; // Acknowledging server name client request.
            len-=2;  // length of extension
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
        default:    // ignore all other extensions
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r;
            len-=2;  // length of extension
            //r=parseoctadorPull(client,&U,tlen,IO,ptr,recv);   // to look at extension
            //printf("Unexpected Extension= "); OCT_output(&U);
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash
    SAL_hashProcessArray(trans_hash,IO->val,ptr);

    OCT_shift_left(IO,ptr);  // Shift octad left - rewind to start 
#if VERBOSITY >= IO_DEBUG
    if (unexp>0)    
    logger((char *)"Unrecognized extensions received\n",NULL,0,NULL);
#endif
    r.val=nb;
    return r;
}

// Receive a Certificate request
ret getCertificateRequest(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,int &nalgs,int *sigalgs)
{
    ret r;
    int i,nb,ext,len,tlen,ptr=0;
    int unexp=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;         // message length 
    r=parseByteorPull(client,IO,ptr,recv); nb=r.val; if (r.err) return r;
    if (nb!=0x00) {
        r.err= MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
        return r;
    }
    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r; // length of extensions

    nalgs=0;
// extension must include signature algorithms
    while (len>0)
    {
        r=parseInt16orPull(client,IO,ptr,recv); ext=r.val; if (r.err) return r;
        len-=2;
        switch (ext)
        {
        case SIG_ALGS :
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r; 
            len-=2;  
            r=parseInt16orPull(client,IO,ptr,recv); nalgs=r.val/2; if (r.err) return r;
            len-=2;
            for (i=0;i<nalgs;i++)
            {
                r=parseInt16orPull(client,IO,ptr,recv); if (r.err) return r;
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
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; 
            len-=2;  // length of extension
            //r=parseoctadorPull(client,&U,tlen,IO,ptr,recv);   // to look at extension
            //printf("Unexpected Extension= "); OCT_output(&U);
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r;
    }

// Update Transcript hash
    SAL_hashProcessArray(trans_hash,IO->val,ptr);
   
    OCT_shift_left(IO,ptr);  // Shift octad left - rewind to start 

    if (nalgs==0) { // must specify at least one signature algorithm
        r.err=UNRECOGNIZED_EXT;
        return r;
    } 
#if VERBOSITY >= IO_DEBUG
    if (unexp>0)    
        logger((char *)"Unrecognized extensions received\n",NULL,0,NULL);
#endif
    r.val=CERT_REQUEST;
    return r;
}

// Get certificate chain, and check its validity 
ret getCheckServerCertificateChain(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,char *hostname,octad *PUBKEY)
{
    ret r;
    int nb,len,ptr=0;
    octad CERTCHAIN;       // // Clever re-use of memory - share memory rather than make a copy!
    CERTCHAIN.len=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;         // message length   
    
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Certificate Chain Length= ",(char *)"%d",len,NULL);
#endif

    r=parseByteorPull(client,IO,ptr,recv); nb=r.val; if (r.err) return r;
    if (nb!=0x00) {
        r.err=MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
        return r;
    }
    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;    // get length of certificate chain
    r=parseoctadorPullptr(client,&CERTCHAIN,len,IO,ptr,recv); if (r.err) return r; // get pointer to certificate chain

// Update Transcript hash
    SAL_hashProcessArray(trans_hash,IO->val,ptr);

    r.err=checkCertChain(&CERTCHAIN,hostname,PUBKEY);

    OCT_shift_left(IO,ptr);  // rewind to start
    r.val=CERTIFICATE;

    return r;
}

// Get Server proof that he owns the Certificate, by receiving its signature SCVSIG on transcript hash
ret getServerCertVerify(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,octad *SCVSIG,int &sigalg)
{
    ret r;
    int nb,len,ptr=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r; // message length    

    OCT_kill(SCVSIG);
    r=parseInt16orPull(client,IO,ptr,recv); sigalg=r.val; if (r.err) return r; // may for example be 0804 - RSA-PSS-RSAE-SHA256
    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;    // sig data follows
    r=parseoctadorPull(client,SCVSIG,len,IO,ptr,recv); if (r.err) return r;
   
// Update Transcript hash
    SAL_hashProcessArray(trans_hash,IO->val,ptr);

    OCT_shift_left(IO,ptr);  // rewind to start
    r.val=CERT_VERIFY;
    return r;
}

// Get handshake finish verifier data in HFIN
ret getServerFinished(Socket &client,octad *IO,crypto *recv,unihash *trans_hash,octad *HFIN)
{
    ret r;
    int nb,len,ptr=0;

    r=getWhatsNext(client,IO,recv,trans_hash); 
    if (r.err) return r;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r;         // message length    

    OCT_kill(HFIN);
    r=parseoctadorPull(client,HFIN,len,IO,ptr,recv); if (r.err) return r;

// Update Transcript hash
    SAL_hashProcessArray(trans_hash,IO->val,ptr);
   
    OCT_shift_left(IO,ptr);  // rewind to start
    r.val=FINISHED;
    return r;
}

// Handshake Retry Request
static const char *hrrh= (const char *)"CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C";

// Process initial serverHello - NOT encrypted
// pskid >=0 if Pre-Shared-Key is accepted
ret getServerHello(Socket &client,octad* SH,int &cipher,int &kex,octad *CID,octad *CK,octad *PK,int &pskid)
{
    ret r;
    int i,tls,svr,left,rtn,silen,cmp,extLen,ext,tmplen,pklen;
    bool retry=false;
    char sid[32];
    octad SID = {0, sizeof(sid), sid};
    char srn[32];
    octad SRN={0,sizeof(srn),srn};    
    char hrr[40];
    octad HRR={0,sizeof(hrr),hrr};

// need this to check for Handshake Retry Request    
    OCT_from_hex(&HRR,(char *)hrrh);

    kex=cipher=-1;
    pskid=-1;

    OCT_kill(CK); OCT_kill(PK);
// get first fragment - not encrypted
    OCT_kill(SH);

// start parsing mandatory components
    int ptr=0;
    r=parseByteorPull(client,SH,ptr,NULL); if (r.err) return r; // should be Server Hello
    if (r.val!=SERVER_HELLO)
    {
        r.err=BAD_HELLO;
        return r;
    }

    r=parseInt24orPull(client,SH,ptr,NULL); left=r.val; if (r.err) return r;   // If not enough, pull in another fragment
    r=parseInt16orPull(client,SH,ptr,NULL); svr=r.val; if (r.err) return r;
    left-=2;                // whats left in message

    if (svr!=TLS1_2) { 
        r.err=NOT_TLS1_3;  // don't ask
        return r;
    }

    r= parseoctadorPull(client,&SRN,32,SH,ptr,NULL); if (r.err) return r;
    left-=32;

    if (OCT_compare(&SRN,&HRR))
    {
        retry=true;        // "random" data was not random at all - indicated Handshake Retry Request!
    }
    r=parseByteorPull(client,SH,ptr,NULL); silen=r.val; if (r.err) return r; 
    left-=1;
    r=parseoctadorPull(client,&SID,silen,SH,ptr,NULL); if (r.err) return r;
    left-=silen;  

// Tricky one. According to the RFC (4.1.3) this check should be made, even though the session id is "legacy",
// Unfortunately it is not made clear if the same session ID should be use on a handshake resumption.
// We note that some servers echo the original id, not a new id associated with a new Client Hello
// Solution here is to use same id on resumption(?)
    if (!OCT_compare(CID,&SID)) { 
        r.err=ID_MISMATCH;  // check identities match
        return r;
    }
    r=parseInt16orPull(client,SH,ptr,NULL); cipher=r.val; if (r.err) return r;
    left-=2;

    r=parseByteorPull(client,SH,ptr,NULL); cmp=r.val; if (r.err) return r;
    left-=1; // Compression not used in TLS1.3
    if (cmp!=0x00) { 
        r.err=NOT_TLS1_3;  // don't ask
        return r;
    }

    r=parseInt16orPull(client,SH,ptr,NULL); extLen=r.val; if (r.err) return r;
    left-=2;  
    if (left!=extLen) { // Check space left is size of extensions
        r.err=BAD_HELLO;
        return r;
    }
// process extensions
    while (extLen>0)
    {
        r=parseInt16orPull(client,SH,ptr,NULL); ext=r.val; if (r.err) return r;
        extLen-=2;
        switch (ext)
        {
        case KEY_SHARE :
            { // actually mandatory
                r=parseInt16orPull(client,SH,ptr,NULL); tmplen=r.val; if (r.err) break;
                extLen-=2;
                extLen-=tmplen;
                r=parseInt16orPull(client,SH,ptr,NULL); kex=r.val; if (r.err) break;
                if (!retry)
                { // its not a retry request
                    r=parseInt16orPull(client,SH,ptr,NULL); pklen=r.val; if (r.err) break;   // FIX this first for HRR
                    r=parseoctadorPull(client,PK,pklen,SH,ptr,NULL); 
                }
                break;
            }
        case PRESHARED_KEY :
            { // Indicate acceptance of pre-shared key
                r=parseInt16orPull(client,SH,ptr,NULL); tmplen=r.val; if (r.err) break;
                extLen-=2;
                extLen-=tmplen;
                r=parseInt16orPull(client,SH,ptr,NULL); pskid=r.val;
                break;
            }
        case COOKIE :
            { // Pick up a cookie
                r=parseInt16orPull(client,SH,ptr,NULL); tmplen=r.val; if (r.err) break;
                extLen-=2;
                extLen-=tmplen;
                r=parseoctadorPull(client,CK,tmplen,SH,ptr,NULL);
                break;
            }
        case TLS_VER :
            { // report TLS version
                r=parseInt16orPull(client,SH,ptr,NULL); tmplen=r.val; if (r.err) break;
                extLen-=2;
                extLen-=tmplen;
                r=parseInt16orPull(client,SH,ptr,NULL); tls=r.val; if (r.err) break; // get TLS version
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

