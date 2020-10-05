// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include "ecdh_NIST256.h"  
#include "ecdh_C25519.h"
#include "randapi.h"  
   
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

// Get expected number of bytes into an octet
int getOctet(int sock,octet *B,int expected)
{
    int more,i=0,len=expected;
    B->len=len;
    while(len>0)
    {
        more=read(sock,&B->val[i],len);
        if (more<0) return -1;
        i+=more;
        len-=more;
    }
    return 0;
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

// parse out a byte from octet M
int parseByte(octet *M,int &ptr)
{
    if (ptr+1>M->len) return -1;
    return (int)(unsigned char)M->val[ptr++];
}

// Get 16-bit Integer from stream
int getInt16(int sock)
{
    char buff[2];
    octet B={0, sizeof(buff), buff};
    getOctet(sock,&B,2);
    return 256*(int)(unsigned char)B.val[0]+(int)(unsigned char)B.val[1];
}

// Get byte from stream
int getByte(int sock)
{
    char b[1];
    octet B={0,sizeof(b),b};
    getOctet(sock,&B,1);
    return (int)(unsigned char)B.val[0];
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

    return 0;
} 
