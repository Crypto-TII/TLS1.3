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


typedef struct
{
    int lifetime;
    int age;
    octet *nonce;
    octet *tick;
} ticket;

using namespace core;

// Build Servername Extension
int extServerName(octet *SN,char *servername)
{
    int len=strlen(servername);
    OCT_clear(SN);
    OCT_jint(SN,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    OCT_jint(SN,5+len,2);   // In theory its a list..
    OCT_jint(SN,3+len,2);   // but only one entry
    OCT_jint(SN,0,1);     // Server is of type DNS Hostname (only one type supported, and only one of each type)
    OCT_jint(SN,len,2);   // serverName length
    OCT_jstring(SN,servername); // servername
    return SN->len;
}
    
// Build Supported Groups Extension
int extSupportedGroups(octet *SG,int nsg,int *supportedGroups)
{
    OCT_clear(SG);
    OCT_jint(SG,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    OCT_jint(SG,2*nsg+2,2);          // Total length
    OCT_jint(SG,2*nsg,2);            // Number of entries
    for (int i=0;i<nsg;i++)          // One entry per supported group 
        OCT_jint(SG,supportedGroups[i],2);
    return SG->len;
}

// Build Signature algorithms Extension
int extSigAlgs(octet *SA,int nsa,int *sigAlgs)
{
    OCT_clear(SA);
    OCT_jint(SA,SIG_ALGS,2);  // This extension is SIGNATURE_ALGORITHMS(0x0d)
    OCT_jint(SA,2*nsa+2,2);   // Total length
    OCT_jint(SA,2*nsa,2);     // Number of entries
    for (int i=0;i<nsa;i++)   // One entry per supported signature algorithm
        OCT_jint(SA,sigAlgs[i],2);
    return SA->len;
}

// Build Client Key Share extension
// Offer a choice of publics keys (some may be PQ!)
int extClientKeyShare(octet *KS,int nalgs,int alg[],octet PK[])
{
    int tlen=0;
    for (int i=0;i<nalgs;i++)
    {
        tlen+=4;
        tlen+=PK[i].len;
    }
    OCT_clear(KS);
    OCT_jint(KS,KEY_SHARE,2); // This extension is KEY_SHARE(0x33)
    OCT_jint(KS,tlen+2,2);
    OCT_jint(KS,tlen,2);
    for (int i=0;i<nalgs;i++)
    {
        OCT_jint(KS,alg[i],2);
        OCT_jint(KS,PK[i].len,2);
        OCT_joctet(KS,&PK[i]);
    }

    return KS->len;
}

int extPSK(octet *PS,int mode)
{
    OCT_clear(PS);
    OCT_jint(PS,PSK_MODE,2);
    OCT_jint(PS,2,2);
    OCT_jint(PS,1,1);
    OCT_jint(PS,mode,1);
    return PS->len;
}

int extVersion(octet *VS,int version)
{
    OCT_clear(VS);
    OCT_jint(VS,TLS_VER,2);
    OCT_jint(VS,3,2);
    OCT_jint(VS,2,1);
    OCT_jint(VS,version,2);
    return VS->len;
}

// Create random octet
int clientRandom(octet *RN,csprng *RNG)
{
    OCT_rand(RN,RNG,32);
    for (int i=0;i<32;i++)    // debug
        RN->val[i]=i;
    return 32;
}

// Create random session ID (not used in TLS1.3)
int sessionID(octet *SI,csprng *RNG)
{
    char r[32];
    octet R={0, sizeof(r), r};
    OCT_rand(&R,RNG,32);
    OCT_clear(SI);
    OCT_jint(SI,32,1);
    OCT_joctet(SI,&R);

    for (int i=0;i<32;i++)     // debug
        SI->val[i+1]=0xe0+i;

    return SI->len;
}

int cipherSuites(octet *CS,int ncs,int *ciphers)
{
    OCT_clear(CS);
    OCT_jint(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_jint(CS,ciphers[i],2);
    return CS->len;
}

// Build Client Hello Octet
int clientHello(octet *CH,char *serverName,int nsc,int *ciphers,int nsg,int *supportedGroups,int nsa,int *sigAlgs,int alg,octet *CPK,int pskMode,int tlsVersion,csprng *RNG)
{
    char sn[100];
    octet SN = {0, sizeof(sn), sn};
    char sg[100];
    octet SG = {0, sizeof(sg), sg};
    char sa[100];
    octet SA = {0, sizeof(sa), sa};
    char ks[100];
    octet KS = {0, sizeof(ks), ks};
    char ps[100];
    octet PS = {0, sizeof(ps), ps};
    char vs[100];
    octet VS = {0, sizeof(vs), vs};
    char rn[32];
    octet RN = {0, sizeof(rn), rn};
    char si[33];
    octet SI = {0, sizeof(si), si};
    char cs[33];
    octet CS = {0, sizeof(cs), cs};
    int clientVersion=0x0303;
    int compressionMethods=0x0100;
    int handshakeHeader=0x0100;

    int algs[4];
    algs[0]=alg;

    char m1[100],m2[100],m3[100],m4[100];
    octet MCPK[4]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3},{0,sizeof(m4),m4}
    };
    OCT_copy(&MCPK[0],CPK);
    
    int total=8;
    total+=clientRandom(&RN,RNG);
    total+=sessionID(&SI,RNG);
    total+=cipherSuites(&CS,nsc,ciphers);

    int extlen=0;
    extlen+=extServerName(&SN,serverName);
    extlen+=extSupportedGroups(&SG,nsg,supportedGroups);
    extlen+=extSigAlgs(&SA,nsa,sigAlgs);
    //extlen+=extClientKeyShare(&KS,alg,CPK);
    extlen+=extClientKeyShare(&KS,1,algs,MCPK);
    extlen+=extPSK(&PS,pskMode);
    extlen+=extVersion(&VS,tlsVersion);

    OCT_clear(CH);
    OCT_fromHex(CH,(char *)"160301");
    OCT_jint(CH,total+extlen+2,2);

    OCT_jint(CH,handshakeHeader,2);
    OCT_jint(CH,total+extlen-2,2);
    OCT_jint(CH,clientVersion,2);
    OCT_joctet(CH,&RN);
    OCT_joctet(CH,&SI);
    OCT_joctet(CH,&CS);
    OCT_jint(CH,compressionMethods,2);
    OCT_jint(CH,extlen,2);
    OCT_joctet(CH,&SN);
    OCT_joctet(CH,&SG);
    OCT_joctet(CH,&SA);
    OCT_joctet(CH,&KS);
    OCT_joctet(CH,&PS);
    OCT_joctet(CH,&VS);

    printf("\nClient Hello= %d ",CH->len); OCT_output(CH);
    return CH->len;
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

// get another fragment of server response
// decrypt and authenticate it
// append it to the end of SR
int getServerResponseFragment(int sock,octet *SHK,octet *SHIV,unsign32 &recno,octet *SR)
{
    int i,left,pos;
    unsigned char b[4];
    char rh[10];
    octet RH={0,sizeof(rh),rh};
    char tag[16];
    octet TAG={0,sizeof(tag),tag};
    char rtag[16];
    octet RTAG={0,sizeof(rtag),rtag};
    char iv[12];
    octet IV={0,sizeof(iv),iv};

// update new IV from original IV and record number
// See RFC8446 section 5.3
// OK should be 64-bit, but really that is excessive
    b[3] = (unsigned char)(recno);
    b[2] = (unsigned char)(recno >> 8);
    b[1] = (unsigned char)(recno >> 16);
    b[0] = (unsigned char)(recno >> 24);
    for (i=0;i<12;i++)
        IV.val[i]=SHIV->val[i];
    for (i=0;i<4;i++)
        IV.val[8+i]^=b[i];
    IV.len=12;
    recno++;

    pos=SR->len;  // current end of SR
// get record Header - should be something like 17 03 03 XX YY
    OCT_clear(&RH);
//printf("Waiting\n");
    getOctet(sock,&RH,3);  // Signed Cert header
//printf("Got a header\n");
    left=getInt16(sock);
    OCT_jint(&RH,left,2);
//    printf("Header= ");OCT_output(&RH);
    getBytes(sock,&SR->val[pos],left-16);  // read in record body

//decrypt body - depends on cipher suite, which is determined by length of key
    gcm g;

    GCM_init(&g,SHK->len,SHK->val,12,IV.val);  // Decrypt with Server handshake Key and IV
    GCM_add_header(&g,RH.val,RH.len);
    GCM_add_cipher(&g,&SR->val[pos],&SR->val[pos],left-16);
//check TAG
    GCM_finish(&g,TAG.val); TAG.len=16;
//    printf("TAG= ");OCT_output(&TAG);

    SR->len+=(left-16);    
// read correct TAG from server
    getOctet(sock,&RTAG,16);    // read in TAG
//    printf("Correct TAG= "); OCT_output(&RTAG);
    if (!OCT_comp(&TAG,&RTAG))
    {
        printf("NOT authenticated!\n");
        return -1;
    }
    printf("Server fragment authenticates %d\n",left-16);

// get record ending - encodes record type
    int lb=SR->val[SR->len-1];
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
        getServerResponseFragment(sock,SHK,SHIV,recno,SR); 
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
        getServerResponseFragment(sock,SHK,SHIV,recno,SR); 
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
        getServerResponseFragment(sock,SHK,SHIV,recno,SR); 
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
        getServerResponseFragment(sock,SHK,SHIV,recno,SR); 
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
        getServerResponseFragment(sock,SHK,SHIV,recno,SR); 
        nb=parseOctet(O,len,SR,ptr);
    }
    return nb;
}

// construct encrypted client finished Octet
int clientFinished(octet *CF,octet *K,octet *SIV,octet *H)
{
    char pt[64];
    octet PT={0,sizeof(pt),pt};
    char tag[16];
    octet TAG={0,sizeof(tag),tag};
    int i,totlen=H->len+4+16+1;   // length of record, payload+TAG+1 byte terminator
    OCT_clear(CF);
    OCT_fromHex(CF,(char *)"170303");
    OCT_jint(CF,totlen,2);
    OCT_jbyte(&PT,0x14,1);
    OCT_jint(&PT,H->len,3);
    OCT_joctet(&PT,H);
    OCT_jbyte(&PT,0x16,1); // indicate handshake data

// encrypt it
    gcm g;

    GCM_init(&g,K->len,K->val,12,SIV->val);  // Encrypt with Client handshake Key and IV
    GCM_add_header(&g,CF->val,CF->len);

    GCM_add_plain(&g,PT.val,PT.val,PT.len);
//create TAG
    GCM_finish(&g,TAG.val); TAG.len=16;

    OCT_joctet(CF,&PT);
    OCT_joctet(CF,&TAG);

    return 0;
}

// After its all over try and send a GET to the server as application data
// would hope to get a load of HTML in response??
int clientGET(octet *HL,octet *K,octet *SIV,char *hostname)
{ 
    char pt[128];
    octet PT={0,sizeof(pt),pt};
    char tag[16];
    octet TAG={0,sizeof(tag),tag};
    
    OCT_clear(&PT);
    OCT_jstring(&PT,(char *)"GET / HTTP/1.1"); // standard HTTP GET command
    OCT_jbyte(&PT,0x0d,1); OCT_jbyte(&PT,0x0a,1);        // CRLF
    OCT_jstring(&PT,(char *)"Host: ");
    OCT_jstring(&PT,hostname); //OCT_jstring(&PT,(char *)":443");
    OCT_jbyte(&PT,0x0d,1); OCT_jbyte(&PT,0x0a,1);        // CRLF
    //OCT_jstring(&PT,(char *)"Connection: keep-alive");
    //OCT_jbyte(&PT,0x0d,1); OCT_jbyte(&PT,0x0a,1);        // CRLF
    OCT_jbyte(&PT,0x0d,1); OCT_jbyte(&PT,0x0a,1);        // empty line CRLF
    OCT_jbyte(&PT,0x17,1);  // indicate application data

    printf("PT= %d ",PT.len);OCT_output(&PT);
    OCT_output_string(&PT);

    int totlen=PT.len+16;
    OCT_clear(HL);
    OCT_fromHex(HL,(char *)"170303");
    OCT_jint(HL,totlen,2);

    gcm g;

    GCM_init(&g,K->len,K->val,12,SIV->val);  // Encrypt with Client Application Key and IV
    GCM_add_header(&g,HL->val,HL->len);

    GCM_add_plain(&g,PT.val,PT.val,PT.len);
//create TAG
    GCM_finish(&g,TAG.val); TAG.len=16;

    OCT_joctet(HL,&PT);
    OCT_joctet(HL,&TAG);

    return 0;
}

// parse Server records received after handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
int parseServerRecord(octet *RS,int sock,octet *SAK,octet *SAIV)
{
    int lt,age,nce,nb,len,te,type,nticks,ptr=0;
    unsign32 recno=0;
    bool fin=false;
    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce};
    char tick[256];
    octet TICK={0,sizeof(tick),tick};

    nticks=0; // number of tickets received
    while (1)
    {
        printf("Waiting for Server input \n");
        OCT_clear(RS); ptr=0;
        type=getServerResponseFragment(sock,SAK,SAIV,recno,RS);  // get first fragment
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

// now deals with any kind of fragmentation
// build up server handshake response in SR, decrypting each fragment in-place
int parseServerResponse(octet *SR,int sock,octet *SHK,octet *SHIV,octet *CERTCHAIN,octet *SCVSIG,octet *HFIN,int &hut1,int &hut2,int &hut3) //returns pointers into SR indicating where hashing might end
{
    int nb,sigalg,ht,len,olen,ptr=0;
    bool fin=false;
    unsign32 recno=0;

    OCT_clear(SR);
    getServerResponseFragment(sock,SHK,SHIV,recno,SR);  // get first fragment

    while (1)
    {
        nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
        len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);           // message length
        switch (nb)
        {
        case ENCRYPTED_EXTENSIONS:
            ptr+=len; // skip encrypted extensions for now
            break;
        case CERTIFICATE :
            nb=parseByteorPull(sock,SR,ptr,SHK,SHIV,recno);
            if (nb!=0x00) printf("Something wrong 2 %x\n",nb);  // expecting 0x00 Request context
            len=parseInt24orPull(sock,SR,ptr,SHK,SHIV,recno);   // get length of certificate chain
            olen=parseOctetorPull(sock,CERTCHAIN,len,SR,ptr,SHK,SHIV,recno);
//    printf("Cert Chain= "); OCT_output(CERTCHAIN);
            hut1=ptr;                   // hash up to this point
            break;

        case CERT_VERIFY :
            sigalg=parseInt16orPull(sock,SR,ptr,SHK,SHIV,recno);   // may for example be 0804 - RSA-PSS-RSAE-SHA256
            len=parseInt16orPull(sock,SR,ptr,SHK,SHIV,recno);      // sig data follows
            olen=parseOctetorPull(sock,SCVSIG,len,SR,ptr,SHK,SHIV,recno);
            hut2=ptr;               // and hash up to this point
            break;

        case SERVER_FINISHED :
            olen=parseOctetorPull(sock,HFIN,len,SR,ptr,SHK,SHIV,recno);
            hut3=ptr;              // and finally hash up to this point   
            fin=true;  // now we are done
            break;
        default:
            printf("Unsupported Handshake message type %x\n",nb);
            fin=true;
            break;
        }
        if (fin) break;
    }
    return sigalg;
}

bool getServerHello(int sock,octet* SH,int &cipher,int &kex,int &tls,octet *PK)
{
    char rh[3];
    octet RH={0,sizeof(rh),rh};
    char hh[3];
    octet HH={0,sizeof(hh),hh};
    char skip[70];
    octet SKIP = {0, sizeof(skip), skip};

    kex=cipher=-1;

// get Header
    getOctet(sock,&RH,3);
    int left=getInt16(sock);
// Get length of whats left
// Read in Server Hello
    getOctet(sock,SH,left);
// parse it    

    int ptr=0;
    parseOctet(&HH,2,SH,ptr);
    left=parseInt16(SH,ptr);
    int svr=parseInt16(SH,ptr); left-=2;

    if (svr!=0x0303)
    {
        printf("Something wrong 1\n");   
        return false;
    }
    parseOctet(&SKIP,32,SH,ptr); left-=32;
    printf("Server Random= "); OCT_output(&SKIP);      
    int silen=parseByte(SH,ptr); left-=1;
    parseOctet(&SKIP,silen,SH,ptr); left-=silen;
    cipher=parseInt16(SH,ptr); left-=2;
    printf("Cipher suite= %x\n",cipher);
    int cmp=parseByte(SH,ptr); left-=1; // Compression
    if (cmp!=0x00)
    {
        printf("Something wrong 2\n"); 
        return false;
    }
    int extLen=parseInt16(SH,ptr); left-=2;  

    if (left!=extLen)
    {
        printf("Something wrong 3\n");
        return false;
    }

    int tmplen;
    while (extLen>0)
    {
        int ext=parseInt16(SH,ptr); extLen-=2;
        switch (ext)
        {
        case KEY_SHARE :
            {
                tmplen=parseInt16(SH,ptr); extLen-=2;
                extLen-=tmplen;
                kex=parseInt16(SH,ptr);
                int pklen=parseInt16(SH,ptr);
                parseOctet(PK,pklen,SH,ptr);
                printf("Key Share = %04x\n",kex);
                printf("Server Public Key= "); OCT_output(PK);
                break;
            }
        case TLS_VER :
            {
                tmplen=parseInt16(SH,ptr); extLen-=2;
                extLen-=tmplen;
                tls=parseInt16(SH,ptr);  // get TLS version
                break;
            }
       default :
            printf("New one on me\n");
            return false;
        break;           
        }
    }
    return true;
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
    char hostname[80];
    char ip[40];
    int tls, sock, valread, port; 
    int cipher_suite,kex,sha;
    char digest[64];

    char b[100];
    octet B = {0, sizeof(b), b};
    char spk[140];
    octet SPK = {0, sizeof(spk), spk};
    char ss[64];
    octet SS = {0, sizeof(ss), ss};

    char ch[1000];
    octet CH = {0, sizeof(ch), ch};
    char sh[1000];
    octet SH = {0, sizeof(sh), sh};
    char hs[64];
    octet HS = {0,sizeof(hs),hs};
    char lb[64];
    octet LB = {0,sizeof(lb),lb};
    char ctx[64];
    octet CTX = {0,sizeof(ctx),ctx};
    char hh[64];
    octet HH={0,sizeof(hh),hh};
    char fh[64];
    octet FH={0,sizeof(fh),fh};
    char th[64];
    octet TH={0,sizeof(th),th};
    char chk[64];
    octet CHK={0,sizeof(chk),chk};
    char shk[64];
    octet SHK={0,sizeof(shk),shk};
    char chiv[12];
    octet CHIV={0,sizeof(chiv),chiv};
    char shiv[12];
    octet SHIV={0,sizeof(shiv),shiv};
    char shts[64];
    octet SHTS={0,sizeof(shts),shts};
    char chts[64];
    octet CHTS={0,sizeof(chts),chts};

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
    {
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
// tls13.cloudflare.com:443
    sock=setclientsock(port,ip);

// For Transcript hash must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;

// Client Side Key Exchange 

    char sk[70];
    octet SK = {0, sizeof(sk), sk};
    char cpk[140];
    octet CPK = {0, sizeof(cpk), cpk};

// Random secret key
    OCT_rand(&SK,&RNG,32);

// For debug only - a secret key
//    OCT_fromHex(&SK,(char *)"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

// RFC 7748
    OCT_reverse(&SK);
    SK.val[32-1]&=248;  
    SK.val[0]&=127;
    SK.val[0]|=64;

    C25519::ECP_KEY_PAIR_GENERATE(NULL, &SK, &CPK);

    OCT_reverse(&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

//    char *serverName=(char *)"example.ulfheim.net";
    char *serverName=(char *)"tls13.cloudflare.com";

// Server Capabilities to be advertised
// Supported Cipher Suits
    int nsc=2;      // ********************
    int ciphers[4];
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
    ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not actually supported
  //  ciphers[3]=0x00ff;

// Supported Key Exchange Groups
    int nsg=3;
    int supportedGroups[3];
    supportedGroups[0]=X25519;
    supportedGroups[1]=SECP256R1;
    supportedGroups[2]=SECP384R1;

// Supported Cert signing Algorithms
    int nsa=9;
    int sigAlgs[10];
    sigAlgs[0]=ECDSA_SECP256R1_SHA256;
    sigAlgs[1]=RSA_PSS_RSAE_SHA256;
    sigAlgs[2]=RSA_PKCS1_SHA256;
    sigAlgs[3]=ECDSA_SECP384R1_SHA384;
    sigAlgs[4]=RSA_PSS_RSAE_SHA384;
    sigAlgs[5]=RSA_PKCS1_SHA384;
    sigAlgs[6]=RSA_PSS_RSAE_SHA512;
    sigAlgs[7]=RSA_PKCS1_SHA512;
    sigAlgs[8]=RSA_PKCS1_SHA1;

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    int alg=X25519;

// create Client Hello Octet
    clientHello(&CH,serverName,nsc,ciphers,nsg,supportedGroups,nsa,sigAlgs,alg,&CPK,pskMode,tlsVersion,&RNG);
    sendOctet(sock,&CH);      // transmit it
    printf("Client Hello sent\n");
    getServerHello(sock,&SH,cipher_suite,kex,tls,&SPK);
    printf("Server Hello received\n");
    printf("Server Hello= %d ",SH.len); OCT_output(&SH);

    if (tls!=TLS1_3)
    {
        printf("Site does not support TLS1.3 - ABORT\n");
        exit(0);
    }

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
        
    Hash_Init(sha,&tlshash);

// Hash Transcript Hellos 
    OCT_shl(&CH,5);  // -  strip off client header
    for (int i=0;i<CH.len;i++)
        Hash_Process(&tlshash,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        Hash_Process(&tlshash,SH.val[i]);

    Hash_Output(&tlshash,digest);
    printf("Hash= "); for (int i=0;i<sha;i++) printf("%02x",(unsigned char)digest[i]); printf("\n");
    
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

    char sr[8000];
    octet SR={0,sizeof(sr),sr};
    char certchain[8000];
    octet CERTCHAIN={0,sizeof(certchain),certchain};
    char scvsig[1024];
    octet SCVSIG={0,sizeof(scvsig),scvsig};
    char fin[200];
    octet FIN={0,sizeof(fin),fin};

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Hash and Shared secret
    GET_HANDSHAKE_SECRETS(cipher_suite,&HS,&CHK,&CHIV,&SHK,&SHIV,&CHTS,&SHTS,&HH,&SS);

// Client now receives certificate and verifier. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note CA signature might use old methods, but server will use PSS padding for its signature (if ECC).

    getSCCS(sock);

    int hut1,hut2,hut3;
// parse Server Response - extract certchain plus server cert verifier plus server finish
    int sigalg=parseServerResponse(&SR,sock,&SHK,&SHIV,&CERTCHAIN,&SCVSIG,&FIN,hut1,hut2,hut3); // returns pointers into SR indicating where hashing can end

    printf("Cert Chain= %d ",CERTCHAIN.len); OCT_output(&CERTCHAIN);
    printf("Signature Algorithm= %04x\n",sigalg);
    printf("Server Certificate Signature= %d ",SCVSIG.len); OCT_output(&SCVSIG);
    printf("Server Verify Data= %d ",FIN.len); OCT_output(&FIN);

    char scert[2000];
    octet SCERT={0,sizeof(scert),scert};

    char cert[5000];
    octet CERT={0,sizeof(cert),cert};
    char cakey[1000];
    octet CAKEY = {0, sizeof(cakey), cakey};

// check certificate chain, and extract Server Cert
    if (CHECK_CERT_CHAIN(&CERTCHAIN,&CAKEY))
        printf("Certificate Chain is valid\n");
    else
        printf("Certificate is NOT valid\n");

// Continue Hashing Transcript

    for (int i=0;i<hut1;i++)
        Hash_Process(&tlshash,SR.val[i]);
    Hash_Output(&tlshash,digest);  // up to end of Server cert

    OCT_clear(&HH);
    OCT_jbytes(&HH,digest,sha);
    printf("1. Hash= "); OCT_output(&HH);

    for (int i=hut1;i<hut2;i++)
        Hash_Process(&tlshash,SR.val[i]);
    Hash_Output(&tlshash,digest);   // up to end of Server Verifier

    OCT_clear(&FH);
    OCT_jbytes(&FH,digest,sha);
    printf("2. Hash= "); OCT_output(&FH);

    for (int i=hut2;i<hut3;i++)
        Hash_Process(&tlshash,SR.val[i]);    
    Hash_Output(&tlshash,digest);   // up to end of Server Finish

    OCT_clear(&TH);
    OCT_jbytes(&TH,digest,sha);
    printf("3. Hash= "); OCT_output(&TH);

// traffic keys

    char cak[32];
    octet CAK={0,sizeof(cak),cak};
    char sak[32];
    octet SAK={0,sizeof(sak),sak};
    char caiv[32];
    octet CAIV={0,sizeof(caiv),caiv};
    char saiv[32];
    octet SAIV={0,sizeof(saiv),saiv};

    GET_APPLICATION_SECRETS(cipher_suite,&CAK,&CAIV,&SAK,&SAIV,&TH,&HS);

    if (IS_SERVER_CERT_VERIFY(sigalg,&SCVSIG,&HH,&CAKEY))
        printf("Server Cert Verification OK\n");
    else
        printf("Server Cert Verification failed\n");

    if (IS_VERIFY_DATA(sha,&FIN,&SHTS,&FH))
        printf("Data is verified\n");
    else
        printf("Data is NOT verified\n");

    sendCCCS(sock);  // send Client Cipher Change

    char cf[128];   // client finish
    octet CF={0,sizeof(cf),cf};

    char chf[64];   // client verify
    octet CHF={0,sizeof(chf),chf};

    char get[128];
    octet GET={0,sizeof(get),get};

    VERIFY_DATA(sha,&CHF,&CHTS,&TH);  // create client verify data

    printf("Client Verify Data= "); OCT_output(&CHF);

    clientFinished(&CF,&CHK,&CHIV,&CHF); // wrap it up
    clientGET(&GET,&CAK,&CAIV,hostname);

    printf("Client Finished= "); OCT_output(&CF);
    printf("Client GET= "); OCT_output(&GET);

    sendOctet(sock,&CF);  // send it
    sendOctet(sock,&GET);    // should get a load of HTML in response??

    char rs[10000];
    octet RS={0,sizeof(rs),rs};

    parseServerRecord(&RS,sock,&SAK,&SAIV); // get tickets

    return 0;
} 
