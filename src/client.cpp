// Client side C/C++ program to demonstrate Socket programming 
// g++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_hash.cpp tls_scv.cpp tls_cert_chain.cpp tls_parse_octet.cpp x509.cpp core.a -o client
#include <stdio.h> 
#include <sys/socket.h> 

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include "core.h"
#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "ecdh_C25519.h"
#include "rsa_RSA2048.h"
#include "randapi.h"  
#include "x509.h"
#include "tls1_3.h" 
#include "tls_sockets.h"
#include "tls_keys_calc.h"
#include "tls_hash.h"
#include "tls_scv.h"
#include "tls_parse_octet.h"
#include "tls_cert_chain.h"

// Ticket Structure
typedef struct
{
    int lifetime;
    int age;
    octet *nonce;
    octet *tick;
} ticket;

using namespace core;

// Build Pre-Shared Key Share Extension
void addPresharedKeyExt(octet *EXT,octet *TICK,unsign32 obf_age,octet* BD)
{
    int len=4+TICK->len+BD->len;
    char psk[1024];
    octet PSK={0,sizeof(psk),psk};
    OCT_jint(&PSK,PRESHARED_KEY,2);

}

// Build Servername Extension
void addServerNameExt(octet *EXT,char *servername)
{
    int len=strlen(servername);
    char sn[TLS_MAX_SERVER_NAME+9];
    octet SN = {0, sizeof(sn), sn};
    OCT_jint(&SN,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    OCT_jint(&SN,5+len,2);   // In theory its a list..
    OCT_jint(&SN,3+len,2);   // but only one entry
    OCT_jint(&SN,0,1);     // Server is of type DNS Hostname (only one type supported, and only one of each type)
    OCT_jint(&SN,len,2);   // serverName length
    OCT_jstring(&SN,servername); // servername
    OCT_joctet(EXT,&SN);
}
    
// Build Supported Groups Extension
void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups)
{
    char sg[6+TLS_MAX_SUPPORTED_GROUPS*2];
    octet SG = {0, sizeof(sg), sg};
    OCT_jint(&SG,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    OCT_jint(&SG,2*nsg+2,2);          // Total length
    OCT_jint(&SG,2*nsg,2);            // Number of entries
    for (int i=0;i<nsg;i++)          // One entry per supported group 
        OCT_jint(&SG,supportedGroups[i],2);
    OCT_joctet(EXT,&SG);
}

// Build Signature algorithms Extension
void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs)
{
    char sa[6+TLS_MAX_SUPPORTED_SIGS*2];
    octet SA={0,sizeof(sa),sa};
    OCT_jint(&SA,SIG_ALGS,2);  // This extension is SIGNATURE_ALGORITHMS(0x0d)
    OCT_jint(&SA,2*nsa+2,2);   // Total length
    OCT_jint(&SA,2*nsa,2);     // Number of entries
    for (int i=0;i<nsa;i++)   // One entry per supported signature algorithm
        OCT_jint(&SA,sigAlgs[i],2);
    OCT_joctet(EXT,&SA);
}

// Add Client Key Share extension
// Offer a choice of publics keys (some may be PQ!)
void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[])
{
    char ks[6+TLS_MAX_KEY_SHARES*(4+TLS_MAX_PUB_KEY_SIZE)];
    octet KS={0,sizeof(ks),ks};
    int tlen=0;
    for (int i=0;i<nalgs;i++)
    {
        tlen+=4;
        tlen+=PK[i].len;
    }
    OCT_jint(&KS,KEY_SHARE,2); // This extension is KEY_SHARE(0x33)
    OCT_jint(&KS,tlen+2,2);
    OCT_jint(&KS,tlen,2);
    for (int i=0;i<nalgs;i++)
    {
        OCT_jint(&KS,alg[i],2);
        OCT_jint(&KS,PK[i].len,2);
        OCT_joctet(&KS,&PK[i]);
    }
    OCT_joctet(EXT,&KS);
}

void addPSKExt(octet *EXT,int mode)
{
    char ps[6];
    octet PS={0,sizeof(ps),ps};
    OCT_jint(&PS,PSK_MODE,2);
    OCT_jint(&PS,2,2);
    OCT_jint(&PS,1,1);
    OCT_jint(&PS,mode,1);
    OCT_joctet(EXT,&PS);
}

void addVersionExt(octet *EXT,int version)
{
    char vs[7];
    octet VS={0,sizeof(vs),vs};
    OCT_jint(&VS,TLS_VER,2);
    OCT_jint(&VS,3,2);
    OCT_jint(&VS,2,1);
    OCT_jint(&VS,version,2);
    OCT_joctet(EXT,&VS);
}

// Create 32-byte random octet
int clientRandom(octet *RN,csprng *RNG)
{
    OCT_rand(RN,RNG,32);
//    for (int i=0;i<32;i++)    // debug
//        RN->val[i]=i;
    return 32;
}

// Create random 32-byte session ID (not used in TLS1.3)
int sessionID(octet *SI,csprng *RNG)
{
    OCT_rand(SI,RNG,32);
    return 1+SI->len;
}

int cipherSuites(octet *CS,int ncs,int *ciphers)
{
    OCT_clear(CS);
    OCT_jint(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_jint(CS,ciphers[i],2);
    return CS->len;
}

// read in SCCS - and ignore it
void getSCCS(int sock)
{
    char rh[3];
    octet RH={0,sizeof(rh),rh};
    char sccs[10];
    octet SCCS={0,sizeof(sccs),sccs};
    getOctet(sock,&RH,3);
    int left=getInt16(sock);
    OCT_joctet(&SCCS,&RH);
    OCT_jint(&SCCS,left,2);
    getBytes(sock,&SCCS.val[5],left);
    SCCS.len+=left;
}

void sendCCCS(int sock)
{
    char cccs[10];
    octet CCCS={0,sizeof(cccs),cccs};
    OCT_fromHex(&CCCS,(char *)"140303000101");
    sendOctet(sock,&CCCS);
}

// Update IV, xor with record number, increment record number
// NIV - New IV
// OIV - Original IV
// See RFC8446 section 5.3
// OK recno should be 64-bit, but really that is excessive
unsign32 updateIV(octet *NIV,octet *OIV,unsign32 recno)
{
    int i;
    unsigned char b[4];  
    b[3] = (unsigned char)(recno);
    b[2] = (unsigned char)(recno >> 8);
    b[1] = (unsigned char)(recno >> 16);
    b[0] = (unsigned char)(recno >> 24);
    for (i=0;i<12;i++)
        NIV->val[i]=OIV->val[i];
    for (i=0;i<4;i++)
        NIV->val[8+i]^=b[i];
    NIV->len=12;
    recno++;  
    return recno;
}

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

    if (SHK==NULL)
    { // not encrypted
        getBytes(sock,&SR->val[pos],left);  // read in record body
        SR->len+=left;
        if (RH.val[0]==0x15)
            return ALERT;
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
    int lb=SR->val[SR->len-1];   // need to track back through zero padding for this....
    SR->len--; // remove it
    if (lb==0x16)
        return HSHAKE;
    if (lb==0x17)
        return APPLICATION;
    if (lb==0x15)
        return ALERT;
    printf("Record does NOT end correctly %x\n",lb);
    return 0;
}

// return Byte, or pull in and decrypt another fragment
int parseByteorPull(int sock,octet *SR,int &ptr,octet *SHK,octet *SHIV,unsign32 &recno)
{
    int nb=parseByte(SR,ptr);
    while (nb < 0)
    { // not enough bytes in SR
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

// Send a client message CM (in a single record). AEAD encrypted if K!=NULL
// recno is count of records sent with this key/IV combo
void sendClientMessage(int sock,int rectype,int version,octet *K,octet *OIV,unsign32 &recno,octet *CM)
{
    int reclen;
    char record[TLS_MAX_CLIENT_RECORD];
    octet RECORD={0,sizeof(record),record};
    char tag[TLS_TAG_SIZE];
    octet TAG={0,sizeof(tag),tag};
    char iv[TLS_IV_SIZE];
    octet IV={0,sizeof(iv),iv};

    if (K==NULL)
    { // no encryption
        OCT_jbyte(&RECORD,rectype,1);
        OCT_jint(&RECORD,version,2);
        reclen=CM->len;
        OCT_jint(&RECORD,reclen,2);
        OCT_joctet(&RECORD,CM); // CM->len
    } else { // encrypted, and sent as application record
        OCT_jbyte(&RECORD,APPLICATION,1);
        OCT_jint(&RECORD,TLS1_2,2);
        reclen=CM->len+16+1;       // 16 for the TAG, 1 for the record type
        OCT_jint(&RECORD,reclen,2);
        OCT_joctet(&RECORD,CM); 
        OCT_jbyte(&RECORD,rectype,1); // append and encrypt actual record type
// could add random padding after this

// AES-GCM
        recno=updateIV(&IV,OIV,recno); // update record number
        gcm g;
        GCM_init(&g,K->len,K->val,12,IV.val);  // Encrypt with Client Application Key and IV
        GCM_add_header(&g,RECORD.val,5);
        GCM_add_plain(&g,&RECORD.val[5],&RECORD.val[5],reclen-16);
//create and append TAG
        GCM_finish(&g,TAG.val); TAG.len=16;
        OCT_joctet(&RECORD,&TAG);
    }
printf("Client to Server -> "); OCT_output(&RECORD);
    sendOctet(sock,&RECORD);
}

// build and transmit client hello. Append pre-prepared extensions
void sendClientHello(int sock,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS)
{
    char rh[5];
    octet RH={0,sizeof(rh),rh};
    char rn[32];
    octet RN = {0, sizeof(rn), rn};
    char cs[2+TLS_MAX_CIPHER_SUITES*2];
    octet CS = {0, sizeof(cs), cs};
    int compressionMethods=0x0100;
    int total=8;
    int extlen=EXTENSIONS->len;
    total+=clientRandom(&RN,RNG);
    total+=sessionID(CID,RNG);
    total+=cipherSuites(&CS,nsc,ciphers);

    OCT_jbyte(&RH,HSHAKE,1);
    OCT_jint(&RH,TLS1_0,2);  // 160301 3
    OCT_jint(&RH,total+extlen+2,2);  // +2 for compression   // 2

    OCT_clear(CH);
    OCT_jbyte(CH,CLIENT_HELLO,1);  // clientHello handshake message  // 1
    OCT_jint(CH,total+extlen-2,3);   // 3

    OCT_jint(CH,TLS1_2,2);              // 2
    OCT_joctet(CH,&RN);              // 32
    OCT_jbyte(CH,CID->len,1);        // 1   
    OCT_joctet(CH,CID);              // 32
    OCT_joctet(CH,&CS);             // 2+TLS_MAX_CIPHER_SUITES*2
    OCT_jint(CH,compressionMethods,2);  // 2

    OCT_jint(CH,extlen,2);            // 2
    OCT_joctet(CH,EXTENSIONS);

// transmit it
    unsign32 nulrec=0;
    sendClientMessage(sock,HSHAKE,TLS1_0,NULL,NULL,nulrec,CH);
}

// send client alert - might be encrypted if K!=NULL
void sendClientAlert(int sock,int type,octet *K,octet *OIV,unsign32 &recno)
{
    char pt[2];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,0x02,1);  // alerts are always fatal
    OCT_jbyte(&PT,type,1);

    sendClientMessage(sock,ALERT,TLS1_2,K,OIV,recno,&PT);
}

// Send final client handshake verification data
void sendClientVerify(int sock,octet *K,octet *OIV,unsign32 &recno,octet *CHF)
{
    char pt[TLS_MAX_HASH+4];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,FINISHED,1);  // indicates handshake message "client finished" 1
    OCT_jint(&PT,CHF->len,3); // .. and its length  3
    OCT_joctet(&PT,CHF);

    sendClientMessage(sock,HSHAKE,TLS1_2,K,OIV,recno,&PT);
}

// parse Server records received after handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
int parseServerRecord(octet *RS,int sock,octet *SAK,octet *SAIV,unsign32 &recno)
{
    int lt,age,nce,nb,len,te,type,nticks,ptr=0;
    bool fin=false;
    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce};
    char tick[TLS_MAX_TICKET_SIZE];
    octet TICK={0,sizeof(tick),tick};

    nticks=0; // number of tickets received
    while (1)
    {
        printf("Waiting for Server input \n");
        OCT_clear(RS); ptr=0;
        type=getServerFragment(sock,SAK,SAIV,recno,RS);  // get first fragment
        //printf("Got another fragment %d\n",type);
        if (type==HSHAKE)
        {
            //printf("Received RS= "); OCT_output(RS);

            while (1)
            {
                nb=parseByteorPull(sock,RS,ptr,SAK,SAIV,recno);
                len=parseInt24orPull(sock,RS,ptr,SAK,SAIV,recno);           // message length
                //printf("nb= %x len= %d\n",nb,len);
                switch (nb)
                {
                case TICKET :
                    lt=parseInt32orPull(sock,RS,ptr,SAK,SAIV,recno);
                    age=parseInt32orPull(sock,RS,ptr,SAK,SAIV,recno);
                    len=parseByteorPull(sock,RS,ptr,SAK,SAIV,recno);
                    printf("lt= %d age= %d nonce len= %d\n",lt,age,len);
                    parseOctetorPull(sock,&NONCE,len,RS,ptr,SAK,SAIV,recno);
    printf("Nonce = "); OCT_output(&NONCE);
                    len=parseInt16orPull(sock,RS,ptr,SAK,SAIV,recno);

                    parseOctetorPull(sock,&TICK,len,RS,ptr,SAK,SAIV,recno);
    printf("Ticket = "); OCT_output(&TICK);
                    te=parseInt16orPull(sock,RS,ptr,SAK,SAIV,recno);
                    ptr+=te;  // skip any ticket extensions
                   // printf("ptr= %d RS->len= %d\n",ptr,RS->len);
                    nticks++;
                    if (ptr==RS->len) fin=true; // record finished
                    if (fin) break;
                    continue;
                default:
                    printf("Unsupported Handshake message type %x\n",nb);
                    fin=true;
                    break;            
                }
                if (fin) break;
            }
            //if (fin) break;
        }
        if (type==APPLICATION)
        {
            printf("Application data (truncated) = ");
            OCT_chop(RS,NULL,20);   // truncate it
            OCT_output(RS);
        }
        if (type==ALERT)
        {
            printf("Alert received from Server - type= "); OCT_output(RS); exit(0);
        }
    }

    return 0;
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

int getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *CID,octet *PK)
{
    int i,tls,left;
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
    if (getServerFragment(sock,NULL,NULL,recno,SH)==ALERT)
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
    {
        printf("Something wrong 3\n");
        return BAD_HELLO;
    }

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
                int pklen=parseInt16orPull(sock,SH,ptr,NULL,NULL,recno);
                parseOctetorPull(sock,PK,pklen,SH,ptr,NULL,NULL,recno);
                printf("Key Share = %04x\n",kex);
                printf("Server Public Key= "); OCT_output(PK);
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

int getIPaddress(char *ip,char *hostname)
{
	hostent * record = gethostbyname(hostname);
	if(record == NULL)
	{
		printf("%s is unavailable\n", hostname);
		exit(1);
	}
	in_addr * address = (in_addr * )record->h_addr;
	strcpy(ip,inet_ntoa(* address));
    return 1;
}

int main(int argc, char const *argv[]) 
{ 
    char hostname[TLS_MAX_SERVER_NAME];
    char ip[40];
    int sock, valread, port, rtn; 
    int cipher_suite,kex,sha;
    char digest[TLS_MAX_HASH];

    char spk[TLS_MAX_PUB_KEY_SIZE];
    octet SPK = {0, sizeof(spk), spk};
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};

    char ch[TLS_MAX_EXTENSIONS+100+TLS_MAX_CIPHER_SUITES*2];
    octet CH = {0, sizeof(ch), ch};
    char sh[TLS_MAX_SERVER_HELLO];
    octet SH = {0, sizeof(sh), sh};
    char hs[TLS_MAX_HASH];
    octet HS = {0,sizeof(hs),hs};
    char hh[TLS_MAX_HASH];
    octet HH={0,sizeof(hh),hh};
    char fh[TLS_MAX_HASH];
    octet FH={0,sizeof(fh),fh};
    char th[TLS_MAX_HASH];
    octet TH={0,sizeof(th),th};
    char chk[TLS_MAX_KEY];
    octet CHK={0,sizeof(chk),chk};
    char shk[TLS_MAX_KEY];
    octet SHK={0,sizeof(shk),shk};
    char chiv[TLS_IV_SIZE];
    octet CHIV={0,sizeof(chiv),chiv};
    char shiv[TLS_IV_SIZE];
    octet SHIV={0,sizeof(shiv),shiv};
    char shts[TLS_MAX_HASH];
    octet SHTS={0,sizeof(shts),shts};
    char chts[TLS_MAX_HASH];
    octet CHTS={0,sizeof(chts),chts};
    char cid[32];                       // Client ID
    octet CID={0,sizeof(cid),cid};

    int i, res;
    unsigned long ran;
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;                // Crypto Strong RNG

    time((time_t *)&ran);

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (i = 4; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG

    argv++; argc--;
    if (argc!=1)
    { // if no parameters, default to localhost
        strcpy(hostname,"localhost");
        strcpy(ip,"127.0.0.1");
        port=44330;
    } else {
        strcpy(hostname,argv[0]);
        printf("Hostname= %s\n",hostname);
        getIPaddress(ip,hostname);
        port=443;
    }
    printf("ip= %s\n",ip);
    sock=setclientsock(port,ip);

// For Transcript hash must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;

// Client Side Key Exchange 

    char sk[TLS_MAX_SECRET_KEY_SIZE];
    octet SK = {0, sizeof(sk), sk};
    char cpk[TLS_MAX_PUB_KEY_SIZE];
    octet CPK = {0, sizeof(cpk), cpk};

// Random secret key
    OCT_rand(&SK,&RNG,32);

// RFC 7748
    OCT_reverse(&SK);
    SK.val[32-1]&=248;  
    SK.val[0]&=127;
    SK.val[0]|=64;

    C25519::ECP_KEY_PAIR_GENERATE(NULL, &SK, &CPK);

    OCT_reverse(&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 


// Client Capabilities to be advertised
// Supported Cipher Suits
    int nsc=2;      // ********************
    int ciphers[TLS_MAX_CIPHER_SUITES];
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
    ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported
  //  ciphers[3]=0x00ff;

// Supported Key Exchange Groups
    int nsg=3;
    int supportedGroups[TLS_MAX_SUPPORTED_GROUPS];
    supportedGroups[0]=X25519;
    supportedGroups[1]=SECP256R1;
    supportedGroups[2]=SECP384R1;

// Supported Cert signing Algorithms
    int nsa=8;
    int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
    sigAlgs[0]=ECDSA_SECP256R1_SHA256;
    sigAlgs[1]=RSA_PSS_RSAE_SHA256;
    sigAlgs[2]=RSA_PKCS1_SHA256;
    sigAlgs[3]=ECDSA_SECP384R1_SHA384;
    sigAlgs[4]=RSA_PSS_RSAE_SHA384;
    sigAlgs[5]=RSA_PKCS1_SHA384;
    sigAlgs[6]=RSA_PSS_RSAE_SHA512;
    sigAlgs[7]=RSA_PKCS1_SHA512;
//    sigAlgs[8]=RSA_PKCS1_SHA1;

// Prepare for extensions
    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    int alg=X25519;

    int algs[TLS_MAX_KEY_SHARES];
    algs[0]=alg;

    char m1[TLS_MAX_PUB_KEY_SIZE],m2[TLS_MAX_PUB_KEY_SIZE],m3[TLS_MAX_PUB_KEY_SIZE],m4[TLS_MAX_PUB_KEY_SIZE];
    octet MCPK[4]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3},{0,sizeof(m4),m4}
    };
    OCT_copy(&MCPK[0],&CPK);

// Client Hello
    char ext[TLS_MAX_EXTENSIONS];
    octet EXT={0,sizeof(ext),ext};

// build client Hello extensions
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,algs,MCPK);
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);

// create and send Client Hello Octet
    sendClientHello(sock,&CH,nsc,ciphers,&RNG,&CID,&EXT);      
    printf("Client Hello sent\n");

// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&SPK);
    if (rtn!=0)
    {
        unsign32 nulrec=0;
        switch (rtn )
        {
        case SH_ALERT :
            printf("Received an alert - "); OCT_output(&SH); exit(0);
        case NOT_TLS1_3 :
            printf("Site does not support TLS 1.3\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
        case HS_RETRY :
            printf("Handshake Retry Request\n"); exit(0);     // TODO - should try again with a new clientHello - with version 0303
        case ID_MISMATCH :
            printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case UNRECOGNIZED_EXT :
            printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case BAD_HELLO :
            printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         default: sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
        }
    }
    printf("Good Server Hello received\n");
    printf("Server Hello= %d ",SH.len); OCT_output(&SH);

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
        
    Hash_Init(sha,&tlshash);

// Hash Transcript Hellos 
    for (int i=0;i<CH.len;i++)
        Hash_Process(&tlshash,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        Hash_Process(&tlshash,SH.val[i]);

    Hash_Output(&tlshash,digest); 
    OCT_jbytes(&HH,digest,sha);

    if (kex==X25519)
    { // RFC 7748
        OCT_reverse(&SPK);
        C25519::ECP_SVDP_DH(&SK, &SPK, &SS,0);
        OCT_reverse(&SS);
    }
    if (kex==SECP256R1)
        NIST256::ECP_SVDP_DH(&SK, &SPK, &SS,1);

    printf("Shared Secret= ");OCT_output(&SS);

    char sr[TLS_MAX_SERVER_RESPONSE];
    octet SR={0,sizeof(sr),sr};
    char certchain[TLS_MAX_CERTCHAIN_SIZE];
    octet CERTCHAIN={0,sizeof(certchain),certchain};
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octet SCVSIG={0,sizeof(scvsig),scvsig};
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Hash and Shared secret
    GET_HANDSHAKE_SECRETS(cipher_suite,&HS,&CHK,&CHIV,&SHK,&SHIV,&CHTS,&SHTS,&HH,&SS);
    unsign32 chkrecno=0;  // number of records encrypted with this key
    unsign32 shkrecno=0;

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note CA signature might use old methods, but server will use PSS padding for its signature (or ECC).

    getSCCS(sock);
// get encrypted extensions
    if (!getServerEncryptedExtensions(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&EXT))
    {
        sendClientAlert(sock,ILLEGAL_PARAMETER,&CHK,&CHIV,chkrecno);
        exit(0);
    }
// get certificate chain
    if (!getServerCertificateChain(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&CERTCHAIN))
    {
        sendClientAlert(sock,ILLEGAL_PARAMETER,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    Hash_Output(&tlshash,HH.val); HH.len=sha;  // hash up to end of Server cert
    printf("1. Transcript Hash= "); OCT_output(&HH);


    char cakey[TLS_MAX_PUB_KEY_SIZE];
    octet CAKEY = {0, sizeof(cakey), cakey};

// check certificate chain, and extract Server Cert Public Key
    if (CHECK_CERT_CHAIN(&CERTCHAIN,&CAKEY))
        printf("Certificate Chain is valid\n");
    else
    {
        printf("Certificate is NOT valid\n");
        exit(0);
    }

// get verifier
    int sigalg=getServerCertVerify(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&SCVSIG);
    if (sigalg<=0)
    {
        sendClientAlert(sock,ILLEGAL_PARAMETER,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    Hash_Output(&tlshash,FH.val); FH.len=sha;  // hash up to end of Server Verifier
    printf("2. Transcript Hash= "); OCT_output(&FH);
    
    printf("Signature Algorithm= %04x\n",sigalg);
    printf("Server Certificate Signature= %d ",SCVSIG.len); OCT_output(&SCVSIG);

    if (IS_SERVER_CERT_VERIFY(sigalg,&SCVSIG,&HH,&CAKEY))
        printf("Server Cert Verification OK\n");
    else
        printf("Server Cert Verification failed\n");

// get Server Finished
    if (!getServerFinished(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&FIN))
    {
        sendClientAlert(sock,ILLEGAL_PARAMETER,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    Hash_Output(&tlshash,TH.val); TH.len=sha;  // hash up to end of Server Finish
    printf("3. Transcript Hash= "); OCT_output(&TH);

    if (IS_VERIFY_DATA(sha,&FIN,&SHTS,&FH))
        printf("Data is verified\n");
    else
        printf("Data is NOT verified\n");

    sendCCCS(sock);  // send Client Cipher Change

    char chf[TLS_MAX_HASH];   // client verify
    octet CHF={0,sizeof(chf),chf};

    VERIFY_DATA(sha,&CHF,&CHTS,&TH);  // create client verify data
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&CHK,&CHIV,chkrecno,&CHF);   


// calculate traffic and application keys
    char cak[TLS_MAX_KEY];
    octet CAK={0,sizeof(cak),cak};
    char sak[TLS_MAX_KEY];
    octet SAK={0,sizeof(sak),sak};
    char caiv[TLS_IV_SIZE];
    octet CAIV={0,sizeof(caiv),caiv};
    char saiv[TLS_IV_SIZE];
    octet SAIV={0,sizeof(saiv),saiv};

    GET_APPLICATION_SECRETS(cipher_suite,&CAK,&CAIV,&SAK,&SAIV,&TH,&HS);
    unsign32 cakrecno=0;  // number of records encrypted with this key
    unsign32 sakrecno=0;

// Start the Application - send HTML GET command
    char get[128];
    octet GET={0,sizeof(get),get};
    OCT_jstring(&GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  14
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF  2
    OCT_jstring(&GET,(char *)"Host: ");  // 6
    OCT_jstring(&GET,hostname); //OCT_jstring(&PT,(char *)":443");
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // empty line CRLF    
    printf("Sending Application Message\n\n"); OCT_output_string(&GET);

    sendClientMessage(sock,APPLICATION,TLS1_2,&CAK,&CAIV,cakrecno,&GET);

    char rs[TLS_MAX_SERVER_RESPONSE];
    octet RS={0,sizeof(rs),rs};

// Server response
    parseServerRecord(&RS,sock,&SAK,&SAIV,sakrecno); // .. first extract tickets

    return 0;
} 
