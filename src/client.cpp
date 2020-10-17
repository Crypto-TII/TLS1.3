// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include "ecdh_NIST256.h"  
#include "ecdh_C25519.h"
#include "rsa_RSA2048.h"
#include "randapi.h"  
#include "x509.h"
   
#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303

#define X25519 0x001d
#define SECP256R1 0x0017
#define SECP384R1 0x0018

#define ECDSA_SECP256R1_SHA256 0x0403
#define RSA_PSS_RSAE_SHA256 0x0804
#define RSA_PKCS1_SHA256 0x0401
#define ECDSA_SECP384R1_SHA384 0x0503
#define RSA_PSS_RSAE_SHA384 0x0805
#define RSA_PKCS1_SHA384 0x0501
#define RSA_PSS_RSAE_SHA512 0x0806
#define RSA_PKCS1_SHA512 0x0601
#define RSA_PKCS1_SHA1 0x0201

#define PSKWECDHE 01
#define TLS1_3 0x0304

#define SERVER_NAME 0x0000
#define SUPPORTED_GROUPS 0x000a
#define SIG_ALGS 0x000d
#define KEY_SHARE 0x0033
#define PSK_MODE 0x002d
#define TLS_VER 0x002b

#define SERVER_NAME 0x0000
#define SUPPORTED_GROUPS 0x000a
#define SIG_ALGS 0x000d
#define KEY_SHARE 0x0033
#define PSK_MODE 0x002d
#define TLS_VER 0x002b

using namespace core;

int setclientsock(int port,char *ip)
{
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(port); 
       
    // Convert IPv4 and IPv6 addresses from text to binary form 
    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 
   
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 
    return sock;
}

// Send Octet
void sendOctet(int sock,octet *B)
{
    send(sock,B->val,B->len,0);
}

// Send Octet length
void sendLen(int sock,int len)
{
    char buff[2];
    octet B={0, sizeof(buff), buff};
    B.len=2;
    B.val[0]=len&0xff;
    B.val[1]=len/256;
    sendOctet(sock,&B);
}

void hashOctet(hash256* sha,octet *X)
{
    for (int i=0;i<X->len;i++)
        HASH256_process(sha,X->val[i]);
}

int getBytes(int sock,char *b,int expected)
{
    int more,i=0,len=expected;
    while(len>0)
    {
        more=read(sock,&b[i],len);
        if (more<0) return -1;
        i+=more;
        len-=more;
    }
    return 0;
}

// Get 16-bit Integer from stream
int getInt16(int sock)
{
    char b[2];
    getBytes(sock,b,2);
    return 256*(int)(unsigned char)b[0]+(int)(unsigned char)b[1];
}

// Get 24-bit Integer from stream
int getInt24(int sock)
{
    char b[3];
    getBytes(sock,b,3);
    return 65536*(int)(unsigned char)b[0]+256*(int)(unsigned char)b[1]+(int)(unsigned char)b[2];
}

// Get byte from stream
int getByte(int sock)
{
    char b[1];
    getBytes(sock,b,1);
    return (int)(unsigned char)b[0];
}

// Get expected number of bytes into an octet
int getOctet(int sock,octet *B,int expected)
{
    B->len=expected;
    return getBytes(sock,B->val,expected);
}

// parse out an octet of length len from octet M into E
int parseOctet(octet *E,int len,octet *M,int &ptr)
{
    if (ptr+len>M->len) return -1;
    E->len=len;
    for (int i=0;i<len;i++ )
        E->val[i]=M->val[ptr++];
    return len;
}

// parse out a 16-bit integer from octet M
int parseInt16(octet *M,int &ptr)
{
    int b0,b1;
    if (ptr+2>M->len) return -1;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    return 256*b0+b1;
}

// parse out a 24-bit integer from octet M
int parseInt24(octet *M,int &ptr)
{
    int b0,b1,b2;
    if (ptr+3>M->len) return -1;
    b0=(int)(unsigned char)M->val[ptr++];
    b1=(int)(unsigned char)M->val[ptr++];
    b2=(int)(unsigned char)M->val[ptr++];
    return 65536*b0+256*b1+b2;
}

// parse out a byte from octet M
int parseByte(octet *M,int &ptr)
{
    if (ptr+1>M->len) return -1;
    return (int)(unsigned char)M->val[ptr++];
}

// Build Extensions..
int extServerName(octet *SN,char *servername)
{
    int len=strlen(servername);
    OCT_clear(SN);
    OCT_jint(SN,SERVER_NAME,2); 
    OCT_jint(SN,5+len,2);
    OCT_jint(SN,3+len,2);
    OCT_jint(SN,0,1);
    OCT_jint(SN,len,2);
    OCT_jstring(SN,servername);
    return SN->len;
}
    
int extSupportedGroups(octet *SG,int nsg,int *supportedGroups)
{
    OCT_clear(SG);
    OCT_jint(SG,SUPPORTED_GROUPS,2);
    OCT_jint(SG,2*nsg+2,2);
    OCT_jint(SG,2*nsg,2);
    for (int i=0;i<nsg;i++)
        OCT_jint(SG,supportedGroups[i],2);
    return SG->len;
}

int extSigAlgs(octet *SA,int nsa,int *sigAlgs)
{
    OCT_clear(SA);
    OCT_jint(SA,SIG_ALGS,2);
    OCT_jint(SA,2*nsa+2,2);
    OCT_jint(SA,2*nsa,2);
    for (int i=0;i<nsa;i++)
        OCT_jint(SA,sigAlgs[i],2);
    return SA->len;
}

int extKeyShare(octet *KS,int alg,octet *PK)
{
    OCT_clear(KS);
    OCT_jint(KS,KEY_SHARE,2);
    OCT_jint(KS,PK->len+6,2);
    OCT_jint(KS,PK->len+4,2);
    OCT_jint(KS,alg,2);
    OCT_jint(KS,PK->len,2);
    OCT_joctet(KS,PK);
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

// create expanded HKDF label LB from label
void hkdfLabel(octet *LB,int length,octet *Label,octet *CTX)
{
    OCT_jint(LB,length,2);
    OCT_jbyte(LB,(char)(6+Label->len),1);
    OCT_jstring(LB,(char *)"tls13 ");
    OCT_joctet(LB,Label);
    if (CTX!=NULL)
    {
        OCT_jbyte(LB, (char)(CTX->len), 1);
        OCT_joctet(LB,CTX);
    } else {
        OCT_jbyte(LB,0,1);
    }
}

// HKDF extension for TLS1.3
void HKDF_Expand_Label(int hash,int hlen,octet *OKM,int olen,octet *PRK,octet *Label,octet *CTX)
{
    char hl[200];
    octet HL={0,sizeof(hl),hl};
    hkdfLabel(&HL,olen,Label,CTX);
    HKDF_Expand(hash,hlen,OKM,olen,PRK,&HL);
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

    int total=8;
    total+=clientRandom(&RN,RNG);
    total+=sessionID(&SI,RNG);
    total+=cipherSuites(&CS,nsc,ciphers);

    int extlen=0;
    extlen+=extServerName(&SN,serverName);
    extlen+=extSupportedGroups(&SG,nsg,supportedGroups);
    extlen+=extSigAlgs(&SA,nsa,sigAlgs);
    extlen+=extKeyShare(&KS,alg,CPK);
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

    printf("\nClient Hello= "); OCT_output(CH);
    printf("ClientHello length= %d\n",CH->len);
    return CH->len;

}
// get wrapper, decrypt it, and parse it!
bool getServerResponse(int sock,octet *SHK,octet *SHIV,octet *SR)
{
    int len=0;
    char rh[5];
    octet RH={0,sizeof(rh),rh};
    char sccs[5];
    octet SCCS={0,sizeof(sccs),sccs};
    char tag[16];
    octet TAG={0,sizeof(tag),tag};
    char rtag[16];
    octet RTAG={0,sizeof(rtag),rtag};

    OCT_clear(SR);

    getOctet(sock,&RH,3);  // strip out SCCS
    int left=getInt16(sock); // get SCCS length
    OCT_joctet(&SCCS,&RH);
    OCT_jint(&SCCS,left,2);
    len+=5;
    getBytes(sock,&SCCS.val[5],left);
    len+=left;
    SCCS.len=len;

// get Header
    len=0;
    OCT_clear(&RH);
    getOctet(sock,&RH,3);  // Signed Cert header
    left=getInt16(sock);
    OCT_jint(&RH,left,2);
    printf("Header= ");OCT_output(&RH);
//    OCT_joctet(SR,&RH);
//    len+=5;
    getBytes(sock,SR->val,left-16);

//decrypt it
    gcm g;
    GCM_init(&g,16,SHK->val,12,SHIV->val);  // Encrypt with Server handshake Key and IV
    GCM_add_header(&g,RH.val,RH.len);

    GCM_add_cipher(&g,SR->val,SR->val,left-16);

//check TAG
    GCM_finish(&g,TAG.val); TAG.len=16;
    printf("TAG= ");OCT_output(&TAG);

    len+=(left-16);
    SR->len=len;    

    getOctet(sock,&RTAG,16);
    printf("RTAG= ");OCT_output(&RTAG);

    if (!OCT_comp(&TAG,&RTAG))
    {
        printf("NOT authenticated!\n");
        return false;
    }
    printf("Server response authenticates\n");
    return true;
}

// read in SCCS - and ignore it
void getSCCS(int sock,octet *SCCS)
{
    char rh[3];
    octet RH={0,sizeof(rh),rh};
    getOctet(sock,&RH,3);
    int left=getInt16(sock);
    OCT_clear(SCCS);
    OCT_joctet(SCCS,&RH);
    OCT_jint(SCCS,left,2);
    getBytes(sock,&SCCS->val[5],left);
    SCCS->len+=left;
}

int parseServerResponse(octet *SR,octet *SCERT,octet *SCV,octet *HFIN) //returns pointer into SR indicating where hashing should end
{
    int hut;
    int ptr=0;
    int ht=parseByte(SR,ptr); // handshake type
    int len=parseInt24(SR,ptr);
    ptr+=len;   // skip extensions

    int nb=parseByte(SR,ptr);
    if (nb!=0x0b) printf("Something wrong 1 %x %x\n",len,nb);
    len=parseInt24(SR,ptr);
    nb=parseByte(SR,ptr);
    if (nb!=0x00) printf("Something wrong 2 %x\n",nb);
    len=parseInt24(SR,ptr); // get length of certificate chain
    len=parseInt24(SR,ptr); // get length of only certificate
    parseOctet(SCERT,len,SR,ptr);
    ptr+=2;     // skip extensions
    hut=ptr;                  // hash up tp this point
    nb=parseByte(SR,ptr);
    if (nb!=0x0f) printf("Something wrong 2 %x\n",nb);
    len=parseInt24(SR,ptr);
    nb=parseInt16(SR,ptr);   // should be 0804
    len=parseInt16(SR,ptr);
    parseOctet(SCV,len,SR,ptr);
    return hut;
}

bool getServerHello(int sock,octet* SH,int &cipher,int &kex,octet *PK)
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

    //printf("Extension length= %x %x\n",extLen,left);
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
                printf("Key Share = %x\n",kex);
                printf("Server Public Key= "); OCT_output(PK);
                break;
            }
        case TLS_VER :
            {
                tmplen=parseInt16(SH,ptr); extLen-=2;
                extLen-=tmplen;
                parseInt16(SH,ptr);  // get TLS version
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

void print_out(char *des, octet *c, int index, int len)
{
    int i;
    printf("%s [", des);
    for (i = 0; i < len; i++)
        printf("%c", c->val[index + i]);
    printf("]\n");
}

void print_date(char *des, octet *c, int index)
{
    int i = index;
    printf("%s [", des);
    if (i == 0) printf("]\n");
    else printf("20%c%c-%c%c-%c%c %c%c:%c%c:%c%c]\n", c->val[i], c->val[i + 1], c->val[i + 2], c->val[i + 3], c->val[i + 4], c->val[i + 5], c->val[i + 6], c->val[i + 7], c->val[i + 8], c->val[i + 9], c->val[i + 10], c->val[i + 11]);
}

#define CHOICE USE_NIST256

int main(int argc, char const *argv[]) 
{ 
    int sock, valread, port; 
    int cipher,kex;
    char digest[32];
    char *ip = (char *)"127.0.0.1";
    char b[100];
    octet B = {0, sizeof(b), b};
    char spk[140];
    octet SPK = {0, sizeof(spk), spk};
    char ss[32];
    octet SS = {0, sizeof(ss), ss};

    char ch[1000];
    octet CH = {0, sizeof(ch), ch};
    char sh[1000];
    octet SH = {0, sizeof(sh), sh};

    char zz[32];
    octet ZZ = {0,sizeof(zz),zz};
    char es[32];
    octet ES = {0,sizeof(es),es};
    char ds[32];
    octet DS = {0,sizeof(ds),ds};
    char ms[32];
    octet MS = {0,sizeof(ms),ms};
    char info[32];
    octet INFO = {0,sizeof(info),info};
    char hs[32];
    octet HS = {0,sizeof(hs),hs};
    char lb[32];
    octet LB = {0,sizeof(lb),lb};
    char ctx[32];
    octet CTX = {0,sizeof(ctx),ctx};
    char hh[32];
    octet HH={0,sizeof(hh),hh};
    char chts[32];
    octet CHTS={0,sizeof(chts),chts};
    char shts[32];
    octet SHTS={0,sizeof(shts),shts};
    char chk[32];
    octet CHK={0,sizeof(chk),chk};
    char shk[32];
    octet SHK={0,sizeof(shk),shk};
    char chiv[32];
    octet CHIV={0,sizeof(chiv),chiv};
    char shiv[32];
    octet SHIV={0,sizeof(shiv),shiv};

    OCT_jbyte(&ZZ,0,32);

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

    port=8080;
    sock=setclientsock(port,ip);

    hash256 sh256;

// Client Side Key Exchange 

    char sk[70];
    octet SK = {0, sizeof(sk), sk};
    char cpk[140];
    octet CPK = {0, sizeof(cpk), cpk};

// For debug only
    OCT_fromHex(&SK,(char *)"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");

// RFC 7748
    OCT_reverse(&SK);
    SK.val[32-1]&=248;  
    SK.val[0]&=127;
    SK.val[0]|=64;

    C25519::ECP_KEY_PAIR_GENERATE(NULL, &SK, &CPK);

    OCT_reverse(&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

    char *serverName=(char *)"example.ulfheim.net";

// Server Capabilities to be advertised
// Supported Cipher Suits
    int nsc=3;
    int ciphers[3];
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
    ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;

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

    HASH256_init(&sh256);

// create Client Hello Octet
    clientHello(&CH,serverName,nsc,ciphers,nsg,supportedGroups,nsa,sigAlgs,alg,&CPK,pskMode,tlsVersion,&RNG);
    sendOctet(sock,&CH);      // transmit it
    printf("Client Hello sent\n");
    getServerHello(sock,&SH,cipher,kex,&SPK);
    printf("Server Hello received\n");

// Hash Hellos 
    OCT_shl(&CH,5);  // -  strip off client header
    for (int i=0;i<CH.len;i++)
        HASH256_process(&sh256,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        HASH256_process(&sh256,SH.val[i]);

    HASH256_hash(&sh256,digest);
    printf("Hash= "); for (int i=0;i<32;i++) printf("%02x",(unsigned char)digest[i]); printf("\n");
    OCT_jbytes(&HH,digest,32);


    if (kex==X25519)
    { // RFC 7748
        OCT_reverse(&SPK);
        C25519::ECP_SVDP_DH(&SK, &SPK, &SS,0);
        OCT_reverse(&SS);
    }
    if (kex==SECP256R1)
    {
        NIST256::ECP_SVDP_DH(&SK, &SPK, &SS,1);
    }    

    printf("Shared Secret= ");OCT_output(&SS);

    HASH256_init(&sh256); 
    HASH256_hash(&sh256,digest); 
    OCT_jbytes(&CTX,digest,32);

    HKDF_Extract(MC_SHA2,32,&ES,&ZZ,&ZZ);

    printf("Early Secret = "); OCT_output(&ES);
    printf("Empty Hash context = "); OCT_output(&CTX);
    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,32,&DS,32,&ES,&INFO,&CTX);

    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,32,&HS,&DS,&SS);

    printf("Handshake Secret= ");OCT_output(&HS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c hs traffic");
    HKDF_Expand_Label(MC_SHA2,32,&CHTS,32,&HS,&INFO,&HH);

    printf("Client handshake traffic secret= ");OCT_output(&CHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s hs traffic");
    HKDF_Expand_Label(MC_SHA2,32,&SHTS,32,&HS,&INFO,&HH);

    printf("Server handshake traffic secret= ");OCT_output(&SHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,32,&CHK,16,&CHTS,&INFO,NULL);

    printf("Client handshake key= "); OCT_output(&CHK);

    HKDF_Expand_Label(MC_SHA2,32,&SHK,16,&SHTS,&INFO,NULL);

    printf("Server handshake key= "); OCT_output(&SHK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,32,&CHIV,12,&CHTS,&INFO,NULL);

    printf("Client handshake IV= "); OCT_output(&CHIV);

    HKDF_Expand_Label(MC_SHA2,32,&SHIV,12,&SHTS,&INFO,NULL);

    printf("Server handshake IV= "); OCT_output(&SHIV);

// Client now receives certificate and verifier. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note CA signature might use old methods, by server will use PSS padding for its signature (if ECC).

    char sccs[20];  // server change cipher spec - not used
    octet SCCS={0,sizeof(sccs),sccs};
    char sr[1200];
    octet SR={0,sizeof(sr),sr};
    char scert[1200];
    octet SCERT={0,sizeof(scert),scert};
    char scvsig[500];
    octet SCVSIG={0,sizeof(scvsig),scvsig};
    char fin[200];
    octet FIN={0,sizeof(fin),fin};

//    getSCCS(sock,&SCCS);
//    printf("server change cipher= "); OCT_output(&SCCS);

    getServerResponse(sock,&SHK,&SHIV,&SR);

    printf("server response= "); OCT_output(&SR);

// Start Hash Transcript

    HASH256_init(&sh256);
    for (int i=0;i<CH.len;i++)
        HASH256_process(&sh256,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        HASH256_process(&sh256,SH.val[i]);

// Hash Transcript
    for (int i=0;i<SR.len-1;i++)   // omit terminating 0x16 from above
        HASH256_process(&sh256,SR.val[i]);
    HASH256_hash(&sh256,digest);
    OCT_clear(&HH);
    OCT_jbytes(&HH,digest,32);
    printf("Hash= "); OCT_output(&HH);

    char emh[64];
    octet EMH = {0,sizeof(emh),emh};   // empty hash
    HASH256_init(&sh256); 
    HASH256_hash(&sh256,digest); 
    OCT_jbytes(&EMH,digest,32);


    char zk[32];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    OCT_jbyte(&ZK,0,32);

// traffic keys

    char cts[32];
    octet CTS={0,sizeof(cts),cts};
    char sts[32];
    octet STS={0,sizeof(sts),sts};


    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,32,&DS,32,&HS,&INFO,&EMH);   // Use handshake secret from above
    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,32,&MS,&DS,&ZK);
    printf("Master Secret= ");OCT_output(&MS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,32,&CTS,32,&MS,&INFO,&HH);

    printf("Client application traffic secret= ");OCT_output(&CTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,32,&STS,32,&MS,&INFO,&HH);

    printf("Server application traffic secret= ");OCT_output(&STS);

    char cak[32];
    octet CAK={0,sizeof(cak),cak};
    char sak[32];
    octet SAK={0,sizeof(sak),sak};
    char caiv[32];
    octet CAIV={0,sizeof(caiv),caiv};
    char saiv[32];
    octet SAIV={0,sizeof(saiv),saiv};

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,32,&CAK,16,&CTS,&INFO,NULL);

    printf("Client application key= "); OCT_output(&CAK);

    HKDF_Expand_Label(MC_SHA2,32,&SAK,16,&STS,&INFO,NULL);

    printf("Server application key= "); OCT_output(&SAK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,32,&CAIV,12,&CTS,&INFO,NULL);

    printf("Client application IV= "); OCT_output(&CAIV);

    HKDF_Expand_Label(MC_SHA2,32,&SAIV,12,&STS,&INFO,NULL);

    printf("Server application IV= "); OCT_output(&SAIV);

// parse Server Response - extract Signed cert plus server cert verifier
        int hut=parseServerResponse(&SR,&SCERT,&SCVSIG,&FIN); //returns pointer into SR indicating where hashing should end

    printf("Signed Cert= "); OCT_output(&SCERT);
    printf("Server Certificate Signature= "); OCT_output(&SCVSIG);

// Start Hash Transcript

    HASH256_init(&sh256);
    for (int i=0;i<CH.len;i++)
        HASH256_process(&sh256,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        HASH256_process(&sh256,SH.val[i]);
    for (int i=0;i<hut;i++)
        HASH256_process(&sh256,SR.val[i]);

    HASH256_hash(&sh256,digest);

    OCT_clear(&HH);
    OCT_jbytes(&HH,digest,32);
    printf("Hash= "); OCT_output(&HH);


    pktype st, ca, pt;
    int c,ic,len,sha;

    char sig[512];
    octet SIG={0,sizeof(sig),sig};
    char r[500];
    octet R={0,sizeof(r),r};
    char s[500];
    octet S={0,sizeof(s),s};
    char p1[500];
    octet P1={0,sizeof(p1),p1};
    char p2[500];
    octet P2={0,sizeof(p2),p2};
    char cert[512];
    octet CERT={0,sizeof(cert),cert};

    st = X509_extract_cert_sig(&SCERT, &SIG); // returns signature type

    if (st.type == 0)
    {
        printf("Unable to extract cert signature\n");
        return 0;
    }

    if (st.type == X509_ECC)
    {
        OCT_chop(&SIG, &S, SIG.len / 2);
        OCT_copy(&R, &SIG);
        printf("Certificate's ECC SIG= \n");
        OCT_output(&R);
        OCT_output(&S);
        printf("\n");
    }

    if (st.type == X509_RSA)
    {
        printf("Certificate's RSA SIG= \n");
        OCT_output(&SIG);
        printf("\n");
    }

    if (st.hash == X509_H256) printf("Hashed with SHA256\n");
    if (st.hash == X509_H384) printf("Hashed with SHA384\n");
    if (st.hash == X509_H512) printf("Hashed with SHA512\n");

// Extract Cert from signed Cert

    c = X509_extract_cert(&SCERT, &CERT);
    printf("\nCert= \n");
    OCT_output(&CERT);
    printf("\n");

// show some issuer details
    printf("Issuer Details\n");
    ic = X509_find_issuer(&CERT);
    c = X509_find_entity_property(&CERT, &X509_ON, ic, &len);
    print_out((char *)"owner=", &CERT, c, len);
    c = X509_find_entity_property(&CERT, &X509_CN, ic, &len);
    print_out((char *)"country=", &CERT, c, len);
    c = X509_find_entity_property(&CERT, &X509_EN, ic, &len);
    print_out((char *)"email=", &CERT, c, len);
    printf("\n");

// show some subject details
    printf("Subject Details\n");
    ic = X509_find_subject(&CERT);
    c = X509_find_entity_property(&CERT, &X509_MN, ic, &len);
    print_out((char *)"Name=", &CERT, c, len);
    c = X509_find_entity_property(&CERT, &X509_CN, ic, &len);
    print_out((char *)"country=", &CERT, c, len);
    c = X509_find_entity_property(&CERT, &X509_EN, ic, &len);
    print_out((char *)"email=", &CERT, c, len);
    printf("\n");

    ic = X509_find_validity(&CERT);
    c = X509_find_start_date(&CERT, ic);
    print_date((char *)"start date= ", &CERT, c);
    c = X509_find_expiry_date(&CERT, ic);
    print_date((char *)"expiry date=", &CERT, c);
    printf("\n");


    char cakey[500];
    octet CAKEY = {0, sizeof(cakey), cakey};
    char certkey[500];
    octet CERTKEY = {0, sizeof(certkey), certkey};

    RSA2048::rsa_public_key PK;

    bool self_signed=X509_self_signed(&CERT);

    ca = X509_extract_public_key(&CERT, &CAKEY);

    if (ca.type == 0)
    {
        printf("Not supported by library\n");
        return 0;
    }
    if (self_signed)
    {
        printf("Not self-signed\n");
    }

    if (ca.type == X509_ECC)
    {
        printf("EXTRACTED ECC PUBLIC KEY= \n");
        OCT_output(&CAKEY);
    }
    if (ca.type == X509_RSA)
    {
        printf("EXTRACTED RSA PUBLIC KEY= \n");
        OCT_output(&CAKEY);
        PK.e = 65537; // assuming this!
        RSA2048::RSA_fromOctet(PK.n, &CAKEY);
    }
    printf("\n");

// Cert is self-signed - so check signature

    if (self_signed)
    {
        printf("Checking Self-Signed Signature\n");
        if (ca.type == X509_ECC)
        {
            if (ca.curve != CHOICE)
            {
                printf("Curve is not supported\n");
                return 0;
            }
            res = NIST256::ECP_PUBLIC_KEY_VALIDATE(&CAKEY);
            if (res != 0)
            {
                printf("ECP Public Key is invalid!\n");
                return 0;
            }
            else printf("ECP Public Key is Valid\n");

            sha = 0;

            if (st.hash == X509_H256) sha = SHA256;
            if (st.hash == X509_H384) sha = SHA384;
            if (st.hash == X509_H512) sha = SHA512;
            if (st.hash == 0)
            {
                printf("Hash Function not supported\n");
                return 0;
            }

            if (NIST256::ECP_VP_DSA(sha, &CAKEY, &CERT, &R, &S) != 0)
            {
                printf("***ECDSA Verification Failed\n");
                return 0;
            }
            else
                printf("ECDSA Signature/Verification succeeded \n");
        }

        if (ca.type == X509_RSA)
        {
            if (ca.curve != 2048)
            {
                printf("RSA bit size is not supported\n");
                return 0;
            }

            sha = 0;

            if (st.hash == X509_H256) sha = SHA256;
            if (st.hash == X509_H384) sha = SHA384;
            if (st.hash == X509_H512) sha = SHA512;
            if (st.hash == 0)
            {
                printf("Hash Function not supported\n");
                return 0;
            }
            core::PKCS15(sha, &CERT, &P1);

            RSA2048::RSA_ENCRYPT(&PK, &SIG, &P2);

            if (OCT_comp(&P1, &P2))
                printf("RSA Signature/Verification succeeded \n");
            else
            {
                printf("***RSA Verification Failed\n");
 //           return 0;
            }
        }
    }

    char scv[1200];
    octet SCV={0,sizeof(scv),scv};

    OCT_jbyte(&SCV,32,64);
    OCT_jstring(&SCV,(char *)"TLS 1.3, server CertificateVerify");
    OCT_jbyte(&SCV,0,1);
    OCT_joctet(&SCV,&HH);

    RSA2048::RSA_ENCRYPT(&PK, &SCVSIG, &P2);  // recover what was signed

    if (core::PSS_VERIFY(32,&SCV,&P2))      // Verify its PSS encoding of original
        printf("TLS_PSS signature verified\n");
    else
        printf("TLS_PSS signature FAILED\n");


    return 0;
} 
