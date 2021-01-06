// 
// Process input recieved from Server
//
#include "tls_client_recv.h"

// get another fragment of server response
// If its encrypted, decrypt and authenticate it
// append it to the end of SR
int getServerFragment(int sock,octet *SHK,octet *SHIV,unsign32 &recno,octet *SR)
{
    int i,left,pos;
    char rh[5];
    octet RH={0,sizeof(rh),rh};

    char tag[TLS_TAG_SIZE];
    octet TAG={0,sizeof(tag),tag};
    char rtag[TLS_TAG_SIZE];
    octet RTAG={0,sizeof(rtag),rtag};
    char iv[TLS_IV_SIZE];
    octet IV={0,sizeof(iv),iv};

    pos=SR->len;  // current end of SR
    getOctet(sock,&RH,3);  // Get record Header - should be something like 17 03 03 XX YY
    left=getInt16(sock);
    OCT_jint(&RH,left,2);
//printf("Record Header= "); OCT_output(&RH);
    if (SHK==NULL)
    { // not encrypted
        getBytes(sock,&SR->val[pos],left);  // read in record body
        SR->len+=left;
        if (RH.val[0]==ALERT)
            return ALERT;
        if (RH.val[0]==CHANGE_CIPHER)
            return CHANGE_CIPHER;
        return HSHAKE;
    }

    recno=updateIV(&IV,SHIV,recno);
//    printf("Header= ");OCT_output(&RH);
    getBytes(sock,&SR->val[pos],left-16);  // read in record body

//AES-GCM decrypt body - depends on cipher suite, which is determined by length of key
    gcm g;
    GCM_init(&g,SHK->len,SHK->val,12,IV.val);  // Decrypt with Server Key and IV
    GCM_add_header(&g,RH.val,RH.len);
    GCM_add_cipher(&g,&SR->val[pos],&SR->val[pos],left-16);
    GCM_finish(&g,TAG.val); TAG.len=16;
//    printf("TAG= ");OCT_output(&TAG);

    SR->len+=(left-16);    
    getOctet(sock,&RTAG,16);    // read in correct TAG
//    printf("Correct TAG= "); OCT_output(&RTAG);
    if (!OCT_comp(&TAG,&RTAG))
    {
        printf("NOT authenticated!\n");
        return -1;
    }
    printf("Server fragment authenticates %d\n",left-16);

// get record ending - encodes real (disguised) record type
    int lb=0;
    int pad=0;
    lb=SR->val[SR->len-1]; 
    SR->len--; // remove it
    while (lb==0)
    { // could be zero padding
        lb=SR->val[SR->len-1];   // need to track back through zero padding for this....
        SR->len--; // remove it
        pad++;
    }
    if (pad>0) printf("%d padding bytes removed \n",pad);

    if (lb==0x16)
        return HSHAKE;
    if (lb==0x17)
        return APPLICATION;
    if (lb==0x15)
        return ALERT;
    printf("Record does NOT end correctly %x\n",lb);
    return 0;
}

// These functions parse out a data type from an octet
// They may also have to pull in more bytes from the socket.

// return Byte, or pull in and decrypt another fragment
int parseByteorPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    int nb=parseByte(SR,ptr);
    while (nb < 0)
    { // not enough bytes in SR - Pull in some more
        getServerFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseByte(SR,ptr);
    }
    return nb;
}

// return 32-bit Int, or pull in another fragment and try again
unsigned int parseInt32orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    unsigned int nb=parseInt32(SR,ptr);
    while (nb == (unsigned int)-1)
    { // not enough bytes in SR - pull in another fragment
        getServerFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseInt32(SR,ptr);
    }
    return nb;
}

// return 24-bit Int, or pull in another fragment and try again
int parseInt24orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    int nb=parseInt24(SR,ptr);
    while (nb < 0)
    { // not enough bytes in SR - pull in another fragment
        getServerFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseInt24(SR,ptr);
    }
    return nb;
}

// return 16-bit Int, or pull in another fragment and try again
int parseInt16orPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    int nb=parseInt16(SR,ptr);
    while (nb < 0)
    { // not enough bytes in SR - pull in another fragment
        getServerFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseInt16(SR,ptr);
    }
    return nb;
}

// return Octet O of length len, or pull in another fragment and try again
int parseOctetorPull(int sock,octet *O,int len,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    int nb=parseOctet(O,len,SR,ptr);
    while (nb < 0)
    { // not enough bytes in SR - pull in another fragment
        getServerFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseOctet(O,len,SR,ptr);
    }
    return nb;
}

// Functions to process server response
// now deals with any kind of fragmentation
// build up server handshake response in SR, decrypting each fragment in-place
// extract Certificate Chain, Server Certificate Signature and Server Verifier Data
// return pointers to hashing check-points
bool getServerEncryptedExtensions(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *SEXT)
{
    int nb,len,ptr=0;

    nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
    len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);           // message length    

    if (nb!=ENCRYPTED_EXTENSIONS)
        return false;

    ptr+=len; // skip encrypted extensions for now

    printf("Length of Encrypted Extension= %d\n",len);
// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,SR->val[i]);
   
    OCT_shl(SR,ptr);  // rewind to start

    return true;
}

bool getServerCertificateChain(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *CERTCHAIN)
{
    int nb,len,ptr=0;

    nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
    len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);           // message length    

    if (nb!=CERTIFICATE)
        return false;

    nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
    if (nb!=0x00) printf("Something wrong 2 %x\n",nb);  // expecting 0x00 Request context
    len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);   // get length of certificate chain
    parseOctetorPull(sock,CERTCHAIN,len,SR,ptr,SHK,SHIV,recno);

// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,SR->val[i]);

    OCT_shl(SR,ptr);  // rewind to start

    return true;
}

int getServerCertVerify(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *SCVSIG)
{
    int sigalg,nb,len,ptr=0;

    nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
    len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);           // message length    

    if (nb!=CERT_VERIFY)
        return 0;

    sigalg=parseInt16orPull(sock,SR,ptr,SHK,SHIV,recno);   // may for example be 0804 - RSA-PSS-RSAE-SHA256
    len=parseInt16orPull(sock,SR,ptr,SHK,SHIV,recno);      // sig data follows
    parseOctetorPull(sock,SCVSIG,len,SR,ptr,SHK,SHIV,recno);
   
// Transcript hash
    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,SR->val[i]);

    OCT_shl(SR,ptr);  // rewind to start

    return sigalg;
}

bool getServerFinished(octet *SR,int sock,octet *SHK,octet *SHIV,unsign32 &recno,unihash *trans_hash,octet *HFIN)
{
    int nb,len,ptr=0;

    nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
    len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);           // message length    

    if (nb!=FINISHED)
        return false;

    parseOctetorPull(sock,HFIN,len,SR,ptr,SHK,SHIV,recno);

    for (int i=0;i<ptr;i++)
        Hash_Process(trans_hash,SR->val[i]);
   
    OCT_shl(SR,ptr);  // rewind to start

    return true;
}

int getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *CID,octet *CK,octet *PK)
{
    int i,tls,left,rtn;
    bool retry=false;
    unsign32 recno=0;
    char sid[32];
    octet SID = {0, sizeof(sid), sid};
    char srn[32];
    octet SRN={0,sizeof(srn),srn};    
    hash256 sh;
    char *helloretryrequest=(char *)"HelloRetryRequest";
    char hrr[32];
    octet HRR={0,sizeof(hrr),hrr};

    HASH256_init(&sh);
    for (i=0;i<strlen(helloretryrequest);i++)
        HASH256_process(&sh,(int)helloretryrequest[i]);
    HASH256_hash(&sh,&HRR.val[0]); HRR.len=32;

    kex=cipher=-1;

// get first fragment - not encrypted
// printf("Into Server Hello\n");
    OCT_clear(SH);
    rtn=getServerFragment(sock,NULL,NULL,recno,SH);
    if (rtn==CHANGE_CIPHER)
    { // ignore it
        OCT_clear(SH);
        rtn=getServerFragment(sock,NULL,NULL,recno,SH);
    }
    if (rtn==ALERT)
        return SH_ALERT;

    int ptr=0;
    int nb=parseByteorPull(sock,SH,ptr,NULL,NULL,recno);  // should be Server Hello
    if (nb!=SERVER_HELLO)
        return BAD_HELLO;

    left=parseInt24orPull(sock,SH,ptr,NULL,NULL,recno);   // If not enough, pull in another fragment
    int svr=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); left-=2; 

    if (svr!=TLS1_2)  
        return NOT_TLS1_3;  // don't ask
   
    parseOctetorPull(sock,&SRN,32,SH,ptr,NULL,NULL,recno); left-=32;
    printf("Server Random= "); OCT_output(&SRN);  

    if (OCT_comp(&SRN,&HRR))
    {
        printf("Handshake Retry request!\n");
        retry=true;
    }
    int silen=parseByteorPull(sock,SH,ptr,NULL,NULL,recno); left-=1;
    parseOctetorPull(sock,&SID,silen,SH,ptr,NULL,NULL,recno); left-=silen;  

    if (!OCT_comp(CID,&SID))
        return ID_MISMATCH;

    cipher=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); left-=2;
    printf("Cipher suite= %x\n",cipher);
    int cmp=parseByteorPull(sock,SH,ptr,NULL,NULL,recno); left-=1; // Compression
    if (cmp!=0x00)
        return NOT_TLS1_3;

    int extLen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); left-=2;  
    if (left!=extLen)
        return BAD_HELLO;

    int tmplen;
    while (extLen>0)
    {
        int ext=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); extLen-=2;
        switch (ext)
        {
        case KEY_SHARE :
            {
                tmplen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); extLen-=2;
                extLen-=tmplen;
                kex=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno);
                printf("Key Share = %04x\n",kex);
                if (!retry)
                { // its not a retry request
                    int pklen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno);    // FIX this first for HRR
                    //printf("pklen = %d\n",pklen);
                    //printf("SH= ");OCT_output(SH);
                    parseOctetorPull(sock,PK,pklen,SH,ptr,NULL,NULL,recno);
                    printf("Server Public Key= "); OCT_output(PK);
                }
                break;
            }
        case COOKIE :
            {
                printf("Picked up a cookie\n");
                tmplen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); extLen-=2;
                extLen-=tmplen;
                parseOctetorPull(sock,CK,tmplen,SH,ptr,NULL,NULL,recno);
                printf("Cookie= (Coffee I code fast?) "); OCT_output(CK);
                break;
            }
        case TLS_VER :
            {
                tmplen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno); extLen-=2;
                extLen-=tmplen;
                tls=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno);  // get TLS version
                break;
            }
       default :
            printf("Unrecognized extension= %d\n",ext);
            return UNRECOGNIZED_EXT;
        break;           
        }
    }

    if (tls!=TLS1_3)
        return NOT_TLS1_3;

    if (OCT_comp(&SRN,&HRR))
        return HS_RETRY;

    return 0;
}
