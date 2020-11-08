// Client side C/C++ program to demonstrate Socket programming 
#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include "core.h"
#include "ecdh_NIST256.h"  
#include "ecdh_C25519.h"
#include "rsa_RSA2048.h"
#include "randapi.h"  
#include "x509.h"
#include "tls1_3.h" 
#include "tls_sockets.h"
#include "tls_keys_calc.h"
#include "tls_hash.h"

using namespace core;

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

//    OCT_jint(KS,PK->len+6,2);
//    OCT_jint(KS,PK->len+4,2);
//    OCT_jint(KS,alg,2);
//    OCT_jint(KS,PK->len,2);
//    OCT_joctet(KS,PK);
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

//decrypt it - probably depends on ciher suite??? 16 -> 24 or 32
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

int parseServerResponse(octet *SR,octet *SCERT,octet *SCV,octet *HFIN,int &hut1,int &hut2,int &hut3) //returns pointer into SR indicating where hashing should end
{
    int ptr=0;
    int sigalg;
    int ht=parseByte(SR,ptr); // handshake type 08 - encrypted extensions
    int len=parseInt24(SR,ptr);
    ptr+=len;   // skip encrypted extensions

    int nb=parseByte(SR,ptr);
    if (nb!=0x0b) printf("Something wrong 1 %x %x\n",len,nb);   // 0x0B Certificate message type
    len=parseInt24(SR,ptr);                                     // message length
    nb=parseByte(SR,ptr);
    if (nb!=0x00) printf("Something wrong 2 %x\n",nb);  // Request context
    len=parseInt24(SR,ptr); // get length of certificate chain
    len=parseInt24(SR,ptr); // get length of only certificate
    parseOctet(SCERT,len,SR,ptr);
    ptr+=2;                     // skip Certificate Extensions
    hut1=ptr;                   // hash up to this point
    nb=parseByte(SR,ptr);
    if (nb!=0x0f) printf("Something wrong 2 %x\n",nb);  // 0x0F = Certificate Verify
    len=parseInt24(SR,ptr);
    sigalg=parseInt16(SR,ptr);   // should be 0804 - RSA-PSS-RSAE-SHA256
    len=parseInt16(SR,ptr);  // sig data follows
    parseOctet(SCV,len,SR,ptr);
    hut2=ptr;               // and hash up to this point

    nb=parseByte(SR,ptr); 
    if (nb!=0x14) printf("Something wrong 2 %x\n",nb);  // 0x14 = Server Finish
    len=parseInt24(SR,ptr);
    parseOctet(HFIN,len,SR,ptr);
    hut3=ptr;              // and finally hash up to this point
    return sigalg;
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
    char hs[32];
    octet HS = {0,sizeof(hs),hs};
    char lb[32];
    octet LB = {0,sizeof(lb),lb};
    char ctx[32];
    octet CTX = {0,sizeof(ctx),ctx};
    char hh[32];
    octet HH={0,sizeof(hh),hh};
    char fh[32];
    octet FH={0,sizeof(fh),fh};
    char th[32];
    octet TH={0,sizeof(th),th};
    char chk[32];
    octet CHK={0,sizeof(chk),chk};
    char shk[32];
    octet SHK={0,sizeof(shk),shk};
    char chiv[32];
    octet CHIV={0,sizeof(chiv),chiv};
    char shiv[32];
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

    port=8080;
    sock=setclientsock(port,ip);

// For Transcript hash must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;

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
    ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not actually supported

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
    getServerHello(sock,&SH,cipher,kex,&SPK);
    printf("Server Hello received\n");

// Check which cipher-suite chosen by Server
    if (cipher==TLS_AES_128_GCM_SHA256)
        Hash_Init(32,&tlshash);  // SHA256
    if (cipher==TLS_AES_256_GCM_SHA384)
        Hash_Init(48,&tlshash);

// Hash Transcript Hellos 
    OCT_shl(&CH,5);  // -  strip off client header
    for (int i=0;i<CH.len;i++)
        Hash_Process(&tlshash,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        Hash_Process(&tlshash,SH.val[i]);

    Hash_Output(&tlshash,digest);
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

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Hash and Shared secret
    GET_HANDSHAKE_SECRETS(32,&HS,&CHK,&CHIV,&SHK,&SHIV,&CHTS,&SHTS,&HH,&SS);

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

    int hut1,hut2,hut3;
// parse Server Response - extract Signed cert plus server cert verifier plus server finish
    int sigalg=parseServerResponse(&SR,&SCERT,&SCVSIG,&FIN,hut1,hut2,hut3); //returns pointers into SR indicating where hashing can end

    printf("Signed Cert= "); OCT_output(&SCERT);
    printf("Server Certificate Signature= "); OCT_output(&SCVSIG);

// Continue Hashing Transcript

    for (int i=0;i<hut1;i++)
        Hash_Process(&tlshash,SR.val[i]);
    Hash_Output(&tlshash,digest);  // up to end of Server cert

    OCT_clear(&HH);
    OCT_jbytes(&HH,digest,32);
    printf("1. Hash= "); OCT_output(&HH);

    for (int i=hut1;i<hut2;i++)
        Hash_Process(&tlshash,SR.val[i]);
    Hash_Output(&tlshash,digest);   // up to end of Server Verifier

    OCT_clear(&FH);
    OCT_jbytes(&FH,digest,32);
    printf("2. Hash= "); OCT_output(&FH);

    for (int i=hut2;i<hut3;i++)
        Hash_Process(&tlshash,SR.val[i]);    
    Hash_Output(&tlshash,digest);   // up to end of Server Finish

    OCT_clear(&TH);
    OCT_jbytes(&TH,digest,32);
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

    GET_APPLICATION_SECRETS(32,&CAK,&CAIV,&SAK,&SAIV,&TH,&HS);

// process certificate
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


// Server Certificate Verify
    char scv[1200];
    octet SCV={0,sizeof(scv),scv};

// Message that was signed
    OCT_jbyte(&SCV,32,64);  // 64 spaces
    OCT_jstring(&SCV,(char *)"TLS 1.3, server CertificateVerify");
    OCT_jbyte(&SCV,0,1);  // add 0 character
    OCT_joctet(&SCV,&HH); // add Transcript Hash 

    if (sigalg==RSA_PSS_RSAE_SHA256)
    {
        RSA2048::RSA_ENCRYPT(&PK, &SCVSIG, &P2);  // recover what was signed - assuming 2048-bit RSA

        if (core::PSS_VERIFY(32,&SCV,&P2))      // Verify its PSS encoding of original
            printf("TLS_PSS signature verified\n");
        else
            printf("TLS_PSS signature FAILED\n");
    }
    if (sigalg==ECDSA_SECP256R1_SHA256)
    {
        OCT_chop(&SCVSIG, &S, SCVSIG.len / 2);
        OCT_copy(&R, &SCVSIG);
        if (NIST256::ECP_VP_DSA(32, &CAKEY, &SCV, &R, &S) == 0)
            printf("ECDSA SECP256R1 signature verified\n");
        else
            printf("ECDSA SECP256R1 signature FAILED\n");
    }
//    printf("Server Handshake Finish Verify= "); OCT_output(&FIN);
    if (IS_VERIFY_DATA(32,&FIN,&SHTS,&FH))
        printf("Data is verified\n");
    else
        printf("Data is NOT verified\n");
    return 0;
} 
