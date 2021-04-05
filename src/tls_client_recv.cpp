// 
// Process input received from Server
//

#include "tls_client_recv.h"
#include "tls_cert_chain.h"
#include "tls_logger.h"

// First some functions for parsing values out of an octet string
// parse out an octet of length len from octet M into E
// ptr is a moving pointer through the octet M
ret parseOctet(octet *E,int len,octet *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    if (ptr+len>M->len) return r;   // not enough in M - probably need to read in some more
    E->len=len;
    for (int i=0;i<len && i<E->max;i++ )
        E->val[i]=M->val[ptr++];
    r.val=len; r.err=0;             // it looks OK
    return r;
}

// parse out an octet of length len from octet M
// ptr is a moving pointer through the octet M
// but now E is just a pointer into M
ret parseOctetptr(octet *E,int len,octet *M,int &ptr)
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

// parse out a 16-bit integer from octet M
ret parseInt16(octet *M,int &ptr)
{
    ret r={0,BAD_RECORD};
    int b0,b1;
    if (ptr+2>M->len) return r;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    r.val= 256*b0+b1; r.err=0;
    return r;
}

// parse out a 24-bit integer from octet M
ret parseInt24(octet *M,int &ptr)
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

// parse out an unsigned 32-bit integer from octet M
ret parseInt32(octet *M,int &ptr)
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

// parse out a byte from octet M
ret parseByte(octet *M,int &ptr)
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

// ALL Server to Client input arrives via this function
// Basic function for reading in a record, which may be only a fragment of a larger message

// get another fragment of server response
// If its encrypted, decrypt and authenticate it
// append it to the end of IO
int getServerFragment(Socket &client,crypto *recv,octet *IO)
{
    int i,rtn,left,pos;
    char rh[5];
    octet RH={0,sizeof(rh),rh};

    char tag[TLS_TAG_SIZE];
    octet TAG={0,sizeof(tag),tag};
    char rtag[TLS_TAG_SIZE];
    octet RTAG={0,sizeof(rtag),rtag};

    pos=IO->len;               // current end of IO
    rtn=getOctet(client,&RH,3);  // Get record Header - should be something like 17 03 03 XX YY

// Need to check RH.val for correctness

    if (rtn<0)
        return TIME_OUT;
    if (RH.val[0]==ALERT)
    {
        left=getInt16(client);
        getOctet(client,IO,left);
        return ALERT;
    }
    if (RH.val[0]==CHANGE_CIPHER)
    { // read it, and ignore it
        char sccs[10];
        octet SCCS={0,sizeof(sccs),sccs};
        left=getInt16(client);
        OCT_joctet(&SCCS,&RH);
        OCT_jint(&SCCS,left,2);
        getBytes(client,&SCCS.val[5],left);
        SCCS.len+=left;
        rtn=getOctet(client,&RH,3); // get the next record
    }

    if (RH.val[0]!=HSHAKE && RH.val[0]!=APPLICATION)
        return BAD_RECORD;

    left=getInt16(client);
    OCT_jint(&RH,left,2);
    if (left+pos>IO->max)
    { // this commonly happens with big records of application data from server
//        printf("This happened %d %d\n",left+pos,IO->max);
        return BAD_RECORD;   // record is too big - memory overflow
    }
    if (recv==NULL)
    { // not encrypted
        getBytes(client,&IO->val[pos],left);  // read in record body
        IO->len+=left;
        return HSHAKE;
    }

    getBytes(client,&IO->val[pos],left-16);  // read in record body

//AES-GCM decrypt body - depends on cipher suite, which is determined by length of key
    gcm g;
    GCM_init(&g,recv->K.len,recv->K.val,12,recv->IV.val);  // Decrypt with Server Key and IV
    GCM_add_header(&g,RH.val,RH.len);
    GCM_add_cipher(&g,&IO->val[pos],&IO->val[pos],left-16);
    GCM_finish(&g,TAG.val); TAG.len=16;
// End of AES-GCM

    increment_crypto_context(recv); // update IV

    IO->len+=(left-16);    
    getOctet(client,&RTAG,16);        // read in correct TAG

    if (!OCT_comp(&TAG,&RTAG))      // compare with calculated TAG
        return AUTHENTICATION_FAILURE;

// get record ending - encodes real (disguised) record type
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
        return ALERT;
    return BAD_RECORD;
}

// These functions parse out a data type from an octet
// But they may also have to pull in more bytes from the socket to complete the type.

// return Byte, if necessary pulling in and decrypting another fragment
ret parseByteorPull(Socket &client,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseByte(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - Pull in some more
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {  // Bad input from server (Authentication failure?)
            r.err=rtn;
            break;
        }
        r=parseByte(IO,ptr);
    }
    return r;
}

// return 32-bit Int, or pull in another fragment and try again
ret parseInt32orPull(Socket &client,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseInt32(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {
            r.err=rtn;
            break;
        }
        r=parseInt32(IO,ptr);
    }
    return r;
}

// return 24-bit Int, or pull in another fragment and try again
ret parseInt24orPull(Socket &client,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseInt24(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {
            r.err=rtn;
            break;
        }
        r=parseInt24(IO,ptr);
    }
    return r;
}

// return 16-bit Int, or pull in another fragment and try again
ret parseInt16orPull(Socket &client,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseInt16(IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {
            r.err=rtn;
            break;
        }
        r=parseInt16(IO,ptr);
    }
    return r;
}

// return Octet O of length len, or pull in another fragment and try again
ret parseOctetorPull(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseOctet(O,len,IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {
            r.err=rtn;
            break;
        }
        r=parseOctet(O,len,IO,ptr);
    }
    return r;
}

// return Octet O of length len, or pull in another fragment and try again
ret parseOctetorPullptr(Socket &client,octet *O,int len,octet *IO,int &ptr,crypto *recv)
{
    ret r=parseOctetptr(O,len,IO,ptr);
    while (r.err)
    { // not enough bytes in IO - pull in another fragment
        int rtn=getServerFragment(client,recv,IO); 
        if (rtn<0) {
            r.err=rtn;
            break;
        }
        r=parseOctetptr(O,len,IO,ptr);
    }
    return r;
}

// Function return convention
// return +m; // returns useful value
// return 0; //  OK or non-fatal error
// return -n; // fatal error cause - should generate an alert

// Functions to process server responses
// Deals with any kind of fragmentation
// Build up server handshake response in IO, decrypting each fragment in-place
// extract Encrypted Extensions, Certificate Chain, Server Certificate Signature and Server Verifier Data
// update transcript hash

// Bad actor Server could be throwing anything at us - so be careful

// Extract first byte to determine message type
int getWhatsNext(Socket &client,octet *IO,crypto *recv,unihash *trans_hash)
{
    int nb,ptr=0;
    ret r;
    r=parseByteorPull(client,IO,ptr,recv); nb=r.val; if (r.err) return r.err;

    Hash_Process(trans_hash,IO->val[0]);
    OCT_shl(IO,ptr); 
    return nb;
}

int getServerEncryptedExtensions(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,bool &early_data_accepted)
{
    ret r;
    int nb,ext,len,tlen,mfl,ptr=0;
    int unexp=0;

    nb=getWhatsNext(client,IO,recv,trans_hash); 
    if (nb<0) return nb;
    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;         // message length    

    early_data_accepted=false;
    if (nb!=ENCRYPTED_EXTENSIONS)
        return WRONG_MESSAGE;

    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err; // length of extensions

// extension could include Servers preference for supported groups, which could be
// taken into account by the client for later connections. Here we will ignore it. From RFC:
// "Clients MUST NOT act upon any information found in "supported_groups" prior to successful completion of the handshake"
    while (len>0)
    {
        r=parseInt16orPull(client,IO,ptr,recv); ext=r.val; if (r.err) return r.err;
        len-=2;
        switch (ext)
        {
        case EARLY_DATA :
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val;  // if tlen != 0?
            len-=2;  // length is zero
            early_data_accepted=true;
            if (tlen!=0) return UNRECOGNIZED_EXT;
            break;
        case MAX_FRAG_LENGTH :
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val; if (r.err) return r.err;
            len-=2;
            r=parseByteorPull(client,IO,ptr,recv); mfl=r.val;  // ideally this should the same as requested by client
            len-=tlen;                                       // but server may have ignored this request... :(
            if (tlen!=1) return UNRECOGNIZED_EXT;            // so we ignore this response  
            break;
        default:    // ignore all other extensions
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val;
            len-=2;  // length of extension
            //r=parseOctetorPull(client,&U,tlen,IO,ptr,recv);   // to look at extension
            //printf("Unexpected Extension= "); OCT_output(&U);
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r.err;
    }

// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,IO->val[i]);
   
    OCT_shl(IO,ptr);  // Shift octet left - rewind to start 

    if (unexp>0) return STRANGE_EXTENSION;
    return unexp;
}

int getCertificateRequest(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,int &nalgs,int *sigalgs)
{
    ret r;
    int i,nb,ext,len,tlen,rtn,ptr=0;
    int unexp=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;         // message length 
    r=parseByteorPull(client,IO,ptr,recv); nb=r.val; if (r.err) return r.err;
    if (nb!=0x00) return MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err; // length of extensions

    nalgs=0;
// extension must include signature algorithms
    while (len>0)
    {
        r=parseInt16orPull(client,IO,ptr,recv); ext=r.val; if (r.err) return r.err;
        len-=2;
        switch (ext)
        {
        case SIG_ALGS :
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val;  
            len-=2;  
            r=parseInt16orPull(client,IO,ptr,recv); nalgs=r.val/2; 
            len-=2;
            for (i=0;i<nalgs;i++)
            {
                r=parseInt16orPull(client,IO,ptr,recv);
                if (i<TLS_MAX_SUPPORTED_SIGS) sigalgs[i]=r.val;
                len-=2;
            }
            if (tlen!=2+2*nalgs) return UNRECOGNIZED_EXT;  
            if (nalgs>TLS_MAX_SUPPORTED_SIGS) nalgs=TLS_MAX_SUPPORTED_SIGS;
            break;
        default:    // ignore all other extensions
            r=parseInt16orPull(client,IO,ptr,recv); tlen=r.val;
            len-=2;  // length of extension
            //r=parseOctetorPull(client,&U,tlen,IO,ptr,recv);   // to look at extension
            //printf("Unexpected Extension= "); OCT_output(&U);
            len-=tlen; ptr+=tlen; // skip over it
            unexp++;
            break;
        }
        if (r.err) return r.err;
    }

// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,IO->val[i]);
   
    OCT_shl(IO,ptr);  // Shift octet left - rewind to start 

    if (nalgs==0) return UNRECOGNIZED_EXT; // must specify at least one signature algorithm
    if (unexp>0) return STRANGE_EXTENSION;
    return unexp;
}

// Get certificate chain, and check its validity 
int getCheckServerCertificateChain(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,char *hostname,octet *PUBKEY)
{
    ret r;
    int nb,len,rtn,ptr=0;
    octet CERTCHAIN;       // // Clever re-use of memory - share memory rather than make a copy!
    CERTCHAIN.len=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;         // message length   
    
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Certificate Chain Length= ",(char *)"%d",len,NULL);
#endif

    r=parseByteorPull(client,IO,ptr,recv); nb=r.val; if (r.err) return r.err;
    if (nb!=0x00) return MISSING_REQUEST_CONTEXT;// expecting 0x00 Request context
    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;    // get length of certificate chain
    r=parseOctetorPullptr(client,&CERTCHAIN,len,IO,ptr,recv); if (r.err) return r.err; // get pointer to certificate chain

// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,IO->val[i]);

    if (CHECK_CERT_CHAIN(&CERTCHAIN,hostname,PUBKEY))
        rtn=0;
    else
        rtn=BAD_CERT_CHAIN;

    OCT_shl(IO,ptr);  // rewind to start

    return rtn;
}

// Get Server proof that he owns the Certificate, by receiving its signature SCVSIG on transcript hash
int getServerCertVerify(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *SCVSIG,int &sigalg)
{
    ret r;
    int nb,len,ptr=0;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err; // message length    

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Certify Length= ",(char *)"%d",len,NULL);
#endif


    OCT_clear(SCVSIG);
    r=parseInt16orPull(client,IO,ptr,recv); sigalg=r.val; if (r.err) return r.err; // may for example be 0804 - RSA-PSS-RSAE-SHA256
    r=parseInt16orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;    // sig data follows
    r=parseOctetorPull(client,SCVSIG,len,IO,ptr,recv); if (r.err) return r.err;
   
// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,IO->val[i]);

    OCT_shl(IO,ptr);  // rewind to start

    return 0;
}

// Get handshake finish verifier data in HFIN
int getServerFinished(Socket &client,octet *IO,crypto *recv,unihash *trans_hash,octet *HFIN)
{
    ret r;
    int nb,len,ptr=0;

    nb=getWhatsNext(client,IO,recv,trans_hash); 
    if (nb<0) return nb;

    r=parseInt24orPull(client,IO,ptr,recv); len=r.val; if (r.err) return r.err;         // message length    

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Finish Length= ",(char *)"%d",len,NULL);
#endif

    OCT_clear(HFIN);
    r=parseOctetorPull(client,HFIN,len,IO,ptr,recv); if (r.err) return r.err;

    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,IO->val[i]);
   
    OCT_shl(IO,ptr);  // rewind to start

    return 0;
}

// Process initial serverHello - NOT encrypted
// pskid >=0 if Pre-Shared-Key is accepted
int getServerHello(Socket &client,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK,int &pskid)
{
    ret r;
    int i,tls,svr,left,rtn,silen,cmp,extLen,ext,tmplen,pklen;
    bool retry=false;
    char sid[32];
    octet SID = {0, sizeof(sid), sid};
    char srn[32];
    octet SRN={0,sizeof(srn),srn};    
    hash256 sh;
    char *helloretryrequest=(char *)"HelloRetryRequest";
    char hrr[32];
    octet HRR={0,sizeof(hrr),hrr};

// need this to check for Handshake Retry Request    
    HASH256_init(&sh);
    for (i=0;i<strlen(helloretryrequest);i++)
        HASH256_process(&sh,(int)helloretryrequest[i]);
    HASH256_hash(&sh,&HRR.val[0]); HRR.len=32;

    kex=cipher=-1;
    pskid=-1;

    OCT_clear(CK); OCT_clear(PK);
// get first fragment - not encrypted
    OCT_clear(SH);
    rtn=getServerFragment(client,NULL,SH);

    if (rtn==TIME_OUT)
        return TIME_OUT;
    if (rtn==ALERT)
        return ALERT;

// start parsing mandatory components
    int nb,ptr=0;
    r=parseByteorPull(client,SH,ptr,NULL); nb=r.val; // should be Server Hello
    if (r.err || nb!=SERVER_HELLO)
        return BAD_HELLO;

    r=parseInt24orPull(client,SH,ptr,NULL); left=r.val; if (r.err) return r.err;   // If not enough, pull in another fragment
    r=parseInt16orPull(client,SH,ptr,NULL); svr=r.val; if (r.err) return r.err;
    left-=2;                // whats left in message

    if (svr!=TLS1_2)  
        return NOT_TLS1_3;  // don't ask
   
    r= parseOctetorPull(client,&SRN,32,SH,ptr,NULL); if (r.err) return r.err;
    left-=32;

    if (OCT_comp(&SRN,&HRR))
        retry=true;        // "random" data was not random at all - indicating Handshake Retry Request
   
    r=parseByteorPull(client,SH,ptr,NULL); silen=r.val; if (r.err) return r.err; 
    left-=1;
    r=parseOctetorPull(client,&SID,silen,SH,ptr,NULL); if (r.err) return r.err;
    left-=silen;  

    if (!OCT_comp(CID,&SID))
        return ID_MISMATCH;  // check identities match

    r=parseInt16orPull(client,SH,ptr,NULL); cipher=r.val; if (r.err) return r.err;
    left-=2;

    r=parseByteorPull(client,SH,ptr,NULL); cmp=r.val; if (r.err) return r.err;
    left-=1; // Compression not used in TLS1.3
    if (cmp!=0x00)         
        return NOT_TLS1_3;

    r=parseInt16orPull(client,SH,ptr,NULL); extLen=r.val; if (r.err) return r.err;
    left-=2;  
    if (left!=extLen)
        return BAD_HELLO;

// process extensions
    while (extLen>0)
    {
        r=parseInt16orPull(client,SH,ptr,NULL); ext=r.val; if (r.err) return r.err;
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
                    r=parseOctetorPull(client,PK,pklen,SH,ptr,NULL); 
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
                r=parseOctetorPull(client,CK,tmplen,SH,ptr,NULL);
                break;
            }
        case TLS_VER :
            { // report TLS version
                r=parseInt16orPull(client,SH,ptr,NULL); tmplen=r.val; if (r.err) break;
                extLen-=2;
                extLen-=tmplen;
                r=parseInt16orPull(client,SH,ptr,NULL); tls=r.val; // get TLS version
                break;
            }
       default :
            return UNRECOGNIZED_EXT;
        break;           
        }
        if (r.err) return r.err;
    }

    if (tls!=TLS1_3)       // error if its not TLS 1.3
        return NOT_TLS1_3;

    if (retry)
        return HANDSHAKE_RETRY;

    return rtn;
}
