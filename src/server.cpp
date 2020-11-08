// Server side C/C++ program to demonstrate Socket programming 
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
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

using namespace core;

// parse out an octet of length len from M into E
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


// Create random octet
int serverRandom(octet *RN,csprng *RNG)
{
    OCT_rand(RN,RNG,32);
    for (int i=0;i<32;i++)    // debug
        RN->val[i]=0x70+i;
    return 32;
}

int extKeyShare(octet *KS,int alg,octet *PK)
{
    OCT_clear(KS);
    OCT_jint(KS,KEY_SHARE,2);
    OCT_jint(KS,PK->len+4,2);
    OCT_jint(KS,alg,2);
    OCT_jint(KS,PK->len,2);
    OCT_joctet(KS,PK);
    return KS->len;
}

int extVersion(octet *VS,int version)
{
    OCT_clear(VS);
    OCT_jint(VS,TLS_VER,2);
    OCT_jint(VS,2,2);
    OCT_jint(VS,version,2);
    return VS->len;
}

bool getClientHello(int sock,octet *CH,char *serverName,int &kex, int &nsc,int *ciphers,int &nsg,int *supportedGroups,int &nsa, int *sigAlgs,int &psks,int* pskModes,int &vers,int *tlsVers,octet *SI,octet *PK)
{
    char rh[3];
    octet RH={0,sizeof(rh),rh};
    char hh[3];
    octet HH={0,sizeof(hh),hh};
    char cv[2];
    octet CV={0,sizeof(cv),cv};
    char sn[100];
    octet SN = {0, sizeof(sn), sn};
    char sg[100];
    octet SG = {0, sizeof(sg), sg};
    char skip[70];
    octet SKIP = {0, sizeof(skip), skip};

    kex=nsc=nsg=nsa=psks=vers=-1;

    getOctet(sock,&RH,3);
// Get length of whats left
    int left=getInt16(sock);

// Read in Client Hello
    getOctet(sock,CH,left);

// parse it
    int ptr=0;
    parseOctet(&HH,2,CH,ptr);
    left=parseInt16(CH,ptr);
    int cvr=parseInt16(CH,ptr); left-=2;

    if (cvr!=0x0303)
    {
        printf("Something wrong 1\n");   
        return false;
    }
    parseOctet(&SKIP,32,CH,ptr); left-=32;
    printf("Client Random= "); OCT_output(&SKIP);    
    int silen=parseByte(CH,ptr); left-=1;
    parseOctet(SI,silen,CH,ptr); left-=silen;

    printf("Session ID= "); OCT_output(SI);
    nsc=parseInt16(CH,ptr)/2; left-=2;
    for (int i=0;i<nsc;i++)
    {
        ciphers[i]=parseInt16(CH,ptr);                        // **** Significant - Supported Ciphers
        printf("Cipher Suite= %x\n",ciphers[i]);
    }
    left-=2*nsc;
    int cmp=parseInt16(CH,ptr); left-=2; // Compression

    if (cmp!=0x0100)
    {
        printf("Something wrong 2\n"); 
        return false;
    }
    int extLen=parseInt16(CH,ptr); left-=2;  

    if (left!=extLen)
    {
        printf("Something wrong 3\n");
        return false;
    }
//    printf("Extension length= %x %x\n",extLen,left);

    int tmplen;
    int chosen=0;

    while (extLen>0)
    {
        int ext=parseInt16(CH,ptr); extLen-=2;
        switch (ext)
        {
        case SERVER_NAME :
            {
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                tmplen=parseInt16(CH,ptr);
                int nxbyt=parseByte(CH,ptr);     // should be 0
                int nmlen=parseInt16(CH,ptr);
                parseOctet(&SN,nmlen,CH,ptr);
                printf("Server Name= "); OCT_output_string(&SN); printf("\n");
                for (int i=0;i<SN.len;i++)
                    serverName[i]=SN.val[i];
                serverName[SN.len]=0; // zero terminate string
                break;
            }
        case SUPPORTED_GROUPS :
            {
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                nsg=parseInt16(CH,ptr)/2; 
                for (int i=0;i<nsg;i++)
                {
                    supportedGroups[i]=parseInt16(CH,ptr);
                    printf("Group = %x\n",supportedGroups[i]);
                }
                break;
            }
        case SIG_ALGS :
            {
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                nsa=parseInt16(CH,ptr)/2;
                for (int i=0;i<nsa;i++)
                {
                    sigAlgs[i]=parseInt16(CH,ptr);
                    printf("Signature alg = %x\n",sigAlgs[i]);
                }
                break;
            }
        case KEY_SHARE :
            {       
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                int ksd=parseInt16(CH,ptr);
                while (ksd>0)
                {
                    kex=parseInt16(CH,ptr); ksd-=2;
                    if (chosen)
                    { // already chosen, so skip it
                        int len=parseInt16(CH,ptr); ksd-=2;
                        parseOctet(&SKIP,len,CH,ptr);
                    } else {
                        chosen=kex;   // probably X25519
                        int pklen=parseInt16(CH,ptr); ksd-=2;
                        parseOctet(PK,pklen,CH,ptr); ksd-=pklen;
                        printf("Key Share = %x\n",kex);
                        printf("Client Public Key= "); OCT_output(PK);
                    }
                }
            }
            break;
        case PSK_MODE :
            {
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                psks=parseByte(CH,ptr);
                for (int i=0;i<psks;i++)
                {
                    pskModes[i]=parseByte(CH,ptr);
                    printf("PSK mode = %x\n",pskModes[i]);
                }
                break;
            }
        case TLS_VER :
            {
                tmplen=parseInt16(CH,ptr); extLen-=2;
                extLen-=tmplen;
                vers=parseByte(CH,ptr)/2;
                printf("vers= %d\n",vers);
                for (int i=0;i<vers;i++)
                {
                    tlsVers[i]=parseInt16(CH,ptr);
                    printf("TLS version = %x\n",tlsVers[i]);
                }
                //printf("extLen= %d\n",extLen);
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

int serverHello(octet *SH,int cipherSuite,int alg,octet *SI,octet *SPK,int tlsVersion,csprng *RNG)
{
    char rn[32];
    octet RN = {0, sizeof(rn), rn};
    char ks[100];
    octet KS = {0, sizeof(ks), ks};
    char vs[100];
    octet VS = {0, sizeof(vs), vs};

    int serverVersion=0x0303;
    int handshakeHeader=0x0200;
    int compressionMethod=0x00;

    int total=10;
    total+=serverRandom(&RN,RNG);
    total+=SI->len;
    

    int extlen=0;
    extlen+=extKeyShare(&KS,alg,SPK);
    extlen+=extVersion(&VS,tlsVersion);

    OCT_clear(SH);
    OCT_fromHex(SH,(char *)"160303");
    OCT_jint(SH,total+extlen+2,2);
    OCT_jint(SH,handshakeHeader,2);
    OCT_jint(SH,total+extlen-2,2);
    OCT_jint(SH,serverVersion,2);
    OCT_joctet(SH,&RN);
    OCT_jbyte(SH,SI->len,1);
    OCT_joctet(SH,SI);
    OCT_jint(SH,cipherSuite,2);
    OCT_jint(SH,compressionMethod,1);
    OCT_jint(SH,extlen,2);
    OCT_joctet(SH,&KS);
    OCT_joctet(SH,&VS);

    printf("\nServer Hello= "); OCT_output(SH);
    printf("ServerHello length= %d\n",SH->len);
    return SH->len;
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
    int ciphers[10];
    int supportedGroups[10];
    int sigAlgs[10];
    int pskModes[10];
    int tlsVers[10];

    hash256 sh256;

    int sock,valread,port; 
    char serverName[200];
    char b[100];
    octet B = {0, sizeof(b), b};
    char m[100];
    octet M = {0, sizeof(m), m};
    char cpk[140];
    octet CPK = {0, sizeof(cpk), cpk};
    char sh[1000];
    octet SH = {0, sizeof(sh), sh};
    char ch[1000];
    octet CH = {0, sizeof(ch), ch};
    char si[33];
    octet SI = {0, sizeof(si), si};
    char ss[32];
    octet SS = {0, sizeof(ss), ss};
    char digest[32];

    char hs[32];
    octet HS = {0,sizeof(hs),hs};
    char lb[32];
    octet LB = {0,sizeof(lb),lb};
    char hh[32];
    octet HH={0,sizeof(hh),hh};
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
    sock=setserversock(port);

    OCT_jstring(&M,(char *)"Hello from Mary\n");

    HASH256_init(&sh256);

    int kex,nsc,nsg,nsa,psks,vers;
    getClientHello(sock,&CH,serverName,kex,nsc,ciphers,nsg,supportedGroups,nsa,sigAlgs,psks,pskModes,vers,tlsVers,&SI,&CPK);
    printf("Client Hello received\n");

// select one of the ciphers!

// Server Side Key Exchange 

    char sk[70];
    octet SK = {0, sizeof(sk), sk};
    char spk[140];
    octet SPK = {0, sizeof(spk), spk};

// debug only
    OCT_fromHex(&SK,(char *)"909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");

    if (kex==X25519)
    { // RFC 7748
        OCT_reverse(&SK);
        SK.val[32-1]&=248;  
        SK.val[0]&=127;
        SK.val[0]|=64;
        C25519::ECP_KEY_PAIR_GENERATE(NULL, &SK, &SPK);
        OCT_reverse(&SPK);
    }
    if (kex==SECP256R1)
    {
        NIST256::ECP_KEY_PAIR_GENERATE(&RNG, &SK, &SPK);
    }    

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Server Public key= 0x"); OCT_output(&SPK); 

    serverHello(&SH,TLS_AES_128_GCM_SHA256,kex,&SI,&SPK,TLS1_3,&RNG);
    sendOctet(sock,&SH);
    printf("Server Hello sent\n");

// Hash Hellos 
    OCT_shl(&SH,5);  // -  strip off server header
    for (int i=0;i<CH.len;i++)
        HASH256_process(&sh256,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        HASH256_process(&sh256,SH.val[i]);

    HASH256_hash(&sh256,digest);
    printf("Hash= "); for (int i=0;i<32;i++) printf("%02x",(unsigned char)digest[i]); printf("\n");
    OCT_jbytes(&HH,digest,32);

    if (kex==X25519)
    { // RFC 7748
        OCT_reverse(&CPK);
        C25519::ECP_SVDP_DH(&SK, &CPK, &SS,0);
        OCT_reverse(&SS);
    }
    if (kex==SECP256R1)
    {
        NIST256::ECP_SVDP_DH(&SK, &CPK, &SS,1);
    }    

    printf("Shared Secret= ");OCT_output(&SS);


// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Hash and Shared secret
    GET_HANDSHAKE_SECRETS(32,&HS,&CHK,&CHIV,&SHK,&SHIV,&CHTS,&SHTS,&HH,&SS);

// Start Hash Transcript

    HASH256_init(&sh256);
    for (int i=0;i<CH.len;i++)
        HASH256_process(&sh256,CH.val[i]);
    for (int i=0;i<SH.len;i++)
        HASH256_process(&sh256,SH.val[i]);
    

// Server's turn

    char cert[1200];
    octet CERT={0,sizeof(cert),cert};

// Server certificate + Server Certificate Verifier
// I should really construct this myself, but I don't know private key to create the signature that is the verifier
// Signature is using RSA-PSS-RSAE-SHA256 2048-bit key.
    OCT_fromHex(&CERT,(char*)"0800000200000b00032e0000032a0003253082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a000000f0001040804010017feb533ca6d007d0058257968424bbc3aa6909e9d49557576a520e04a5ef05f0e86d24ff43f8eb861eef595228d7032aa360f714e667413926ef4f8b5803b69e35519e3b23f4373dfac6787066dcb4756b54560e0886e9b962c4ad28dab26bad1abc25916b09af286537f684f808aefee73046cb7df0a84fbb5967aca131f4b1cf389799403a30c02d29cbdadb72512db9cec2e5e1d00e50cafcf6f21091ebc4f253c5eab01a679baeabeedb9c9618f66006b8244d6622aaa56887ccfc66a0f3851dfa13a78cff7991e03cb2c3a0ed87d7367362eb7805b00b2524ff298a4da487cacdeaf8a2336c5631b3efa935bb411e753ca13b015fec7e4a730f1369f9e14000020ea6ee176dccc4af1859e9e4e93f797eac9a78ce439301e35275ad43f3cddbde316");

// Hash Transcript
    for (int i=0;i<CERT.len-1;i++)   // omit terminating 0x16 from above
        HASH256_process(&sh256,CERT.val[i]);
    HASH256_hash(&sh256,digest);
    OCT_clear(&HH);
    OCT_jbytes(&HH,digest,32);
    printf("Hash= "); OCT_output(&HH);

    char sccs[6];  // server change cipher spec - not used
    octet SCCS={0,sizeof(sccs),sccs};
    OCT_fromHex(&SCCS,(char *)"140303000101");
//    sendOctet(sock,&SCCS);
    
// record header
    char rh[5];
    octet RH={0,sizeof(rh),rh};
    OCT_fromHex(&RH,(char *)"1703030475");  
    
    gcm g;
    GCM_init(&g,16,SHK.val,12,SHIV.val);  // Encrypt with Server handshake Key and IV
    GCM_add_header(&g,RH.val,RH.len);

    GCM_add_plain(&g,CERT.val,CERT.val,CERT.len);

    char tag[16];
    octet TAG={0,sizeof(tag),tag};
    GCM_finish(&g,TAG.val); TAG.len=16;

    printf("ciphered cert= ");OCT_output(&CERT);
    printf("authentication tag= "); OCT_output(&TAG);


    char cak[32];
    octet CAK={0,sizeof(cak),cak};
    char sak[32];
    octet SAK={0,sizeof(sak),sak};
    char caiv[32];
    octet CAIV={0,sizeof(caiv),caiv};
    char saiv[32];
    octet SAIV={0,sizeof(saiv),saiv};

    GET_APPLICATION_SECRETS(32,&CAK,&CAIV,&SAK,&SAIV,&HH,&HS);

// Server's Response 
    char sr[2000];
    octet SR = {0, sizeof(sr), sr};

// build server response

    OCT_joctet(&SR,&SCCS);
    OCT_joctet(&SR,&RH);
    OCT_joctet(&SR,&CERT);
    OCT_joctet(&SR,&TAG);

    sendOctet(sock,&SR);

    printf("Server Response= "); OCT_output(&SR);

    return 0;
} 
