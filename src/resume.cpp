// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_hash.cpp tls_scv.cpp tls_cert_chain.cpp tls_parse_octet.cpp tls_client_recv.cpp tls_client_send.cpp core.a -o client

#include <stdio.h> 
#include <fstream>
#include <string.h> 
#include <time.h>
#include <unistd.h>
#include "core.h"
#include "randapi.h"  
#include "x509.h"
#include "tls1_3.h" 
#include "tls_keys_calc.h"
#include "tls_hash.h"
#include "tls_scv.h"
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_client_send.h"

int parseTicket(octet *TICK,octet *NONCE,octet *ETICK,unsign32& obfuscated_age)
{
    int ptr=0;
    int lifetime=parseInt32(TICK,ptr);
    obfuscated_age=parseInt32(TICK,ptr);
    int len=parseByte(TICK,ptr);
    parseOctet(NONCE,len,TICK,ptr);
    len=parseInt16(TICK,ptr);
    parseOctet(ETICK,len,TICK,ptr);
    return lifetime;
}

int main(int argc, char const *argv[]) 
{ 
    char hostname[TLS_MAX_SERVER_NAME];
    char ip[40];
    int sock, valread, port, rtn; 
    int cipher_suite,kex,sha;

    char spk[TLS_MAX_PUB_KEY_SIZE];
    octet SPK = {0, sizeof(spk), spk};   // Servers key exchange Public Key
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};      // Shared Secret

    char ch[TLS_MAX_EXTENSIONS+100+TLS_MAX_CIPHER_SUITES*2];  // Client Hello
    octet CH = {0, sizeof(ch), ch};
    char sh[TLS_MAX_SERVER_HELLO];                            // Server Hello
    octet SH = {0, sizeof(sh), sh};
    char ext[TLS_MAX_EXTENSIONS];
    octet EXT={0,sizeof(ext),ext};      // Extensions                  

    char es[TLS_MAX_HASH];               // Early Secret
    octet ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octet HS = {0,sizeof(hs),hs};

    char hh[TLS_MAX_HASH];               
    octet HH={0,sizeof(hh),hh};          // Transcript hash
    char fh[TLS_MAX_HASH];
    octet FH={0,sizeof(fh),fh};          // Transcript hash up to Server Verify
    char th[TLS_MAX_HASH];
    octet TH={0,sizeof(th),th};          // Transcript hash up to Server's finish

    char chk[TLS_MAX_KEY];
    octet CHK={0,sizeof(chk),chk};       // Clients handshake Key
    char shk[TLS_MAX_KEY];
    octet SHK={0,sizeof(shk),shk};       // Servers handshake Key
    char chiv[TLS_IV_SIZE];
    octet CHIV={0,sizeof(chiv),chiv};    // Clients handshake IV
    char shiv[TLS_IV_SIZE];
    octet SHIV={0,sizeof(shiv),shiv};    // Servers handshake IV
    char shts[TLS_MAX_HASH];
    octet SHTS={0,sizeof(shts),shts};    // Servers handshake traffic secret
    char chts[TLS_MAX_HASH];
    octet CHTS={0,sizeof(chts),chts};    // Clients handshake traffic secret

    char cid[32];                       
    octet CID={0,sizeof(cid),cid};      // Client session ID
    char ck[TLS_MAX_COOKIE];
    octet CK={0,sizeof(ck),ck};         // Cookie
    char sr[TLS_MAX_SERVER_RESPONSE];
    octet SR={0,sizeof(sr),sr};         // Server response
    char certchain[TLS_MAX_CERTCHAIN_SIZE];           
    octet CERTCHAIN={0,sizeof(certchain),certchain};  // Certificate chain
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octet SCVSIG={0,sizeof(scvsig),scvsig};           // Server's deigital signature on transcript
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           // client verify
    octet CHF={0,sizeof(chf),chf};
    char cakey[TLS_MAX_PUB_KEY_SIZE];                 
    octet CAKEY = {0, sizeof(cakey), cakey};          // Server's Cert Public Key

    char sk[TLS_MAX_SECRET_KEY_SIZE];  // clients key exchange secret key
    octet SK = {0, sizeof(sk), sk};
    char cpk[TLS_MAX_PUB_KEY_SIZE];    // clients key exchaneg public key
    octet CPK = {0, sizeof(cpk), cpk};

    char cts[TLS_MAX_HASH];
    octet CTS = {0,sizeof(cts),cts};   // client traffic secret
    char sts[TLS_MAX_HASH];
    octet STS = {0,sizeof(sts),sts};   // server traffic secret
    char cak[TLS_MAX_KEY];
    octet CAK={0,sizeof(cak),cak};     // client application key
    char sak[TLS_MAX_KEY];
    octet SAK={0,sizeof(sak),sak};     // server application key
    char caiv[TLS_IV_SIZE];
    octet CAIV={0,sizeof(caiv),caiv};  // client application IV
    char saiv[TLS_IV_SIZE];
    octet SAIV={0,sizeof(saiv),saiv};  // server application IV

    char rms[TLS_MAX_HASH];
    octet RMS = {0,sizeof(rms),rms};   // client traffic secret

    char raw[100];
    octet RAW = {0, sizeof(raw), raw}; // Some initial entropy

    char rs[TLS_MAX_SERVER_RESPONSE];  // Process server responses post-handshake
    octet RS={0,sizeof(rs),rs};

// choice of up to 3 public keys for key exchange
    char m1[TLS_MAX_PUB_KEY_SIZE],m2[TLS_MAX_PUB_KEY_SIZE],m3[TLS_MAX_PUB_KEY_SIZE];
    octet MCPK[3]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3}
    };

    int supportedGroups[TLS_MAX_SUPPORTED_GROUPS];
    int ciphers[TLS_MAX_CIPHER_SUITES];
    int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
    int algs[TLS_MAX_KEY_SHARES];

    int i, res;
    unsigned long ran;
    csprng RNG;                // Crypto Strong RNG

    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce};
    char tick[TLS_MAX_TICKET_SIZE];
    octet TICK={0,sizeof(tick),tick};
    int lifetime=0;
    unsign32 age_obfuscator;

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
        port=4430;
    } else {
        strcpy(hostname,argv[0]);
        printf("Hostname= %s\n",hostname);
        getIPaddress(ip,hostname);
        port=443;
    }
    printf("ip= %s\n",ip);
    sock=setclientsock(port,ip);

    ifstream back("resume.sta");

    unsigned int fred;
    back >> TICK.len;
    for (int i=0;i<TICK.len;i++)
    {
        back >> fred;
        TICK.val[i]=fred;
    }
    back >> NONCE.len;
    for (int i=0;i<NONCE.len;i++)
    {
        back >> fred;
        NONCE.val[i] = fred;
    }
    back >> RMS.len;
    for (int i=0;i<RMS.len;i++)
    {
        back >> fred;
        RMS.val[i]=fred;
    }

    printf("Recovered Ticket= ");OCT_output(&TICK);

    char etick[TLS_MAX_TICKET_SIZE];
    octet ETICK={0,sizeof(etick),etick};

    lifetime=parseTicket(&TICK,&NONCE,&ETICK,age_obfuscator);

// RESUMPTION
    printf("Ticket details\n");
    printf("life time t= %d minutes\n",lifetime/60);
    printf("Age obfuscator = %08x\n",age_obfuscator);
    printf("Nonce = "); OCT_output(&NONCE);
    printf("Ticket = %d ",ETICK.len); OCT_output(&ETICK);

// recover PSK from Resumption Master Secret and Nonce
    char psk[TLS_MAX_HASH];
    octet PSK={0,sizeof(psk),psk};
    char bkr[TLS_MAX_HASH];
    octet BKR={0,sizeof(bkr),bkr};

    RECOVER_PSK(cipher_suite,&RMS,&NONCE,&PSK);  // recover PSK from resumption master secret and ticket nonce
    printf("PSK= "); OCT_output(&PSK);

    sha=PSK.len;

    GET_EARLY_SECRET(cipher_suite,&PSK,&ES,NULL,&BKR);
    printf("Binder Key= %d ",sha); OCT_output(&BKR);

// try to resume - reopen socket

// choice of up to 3 tickets
    char t1[TLS_MAX_TICKET_SIZE],t2[TLS_MAX_TICKET_SIZE],t3[TLS_MAX_TICKET_SIZE];
    octet PSKID[3]={
        {0,sizeof(t1),t1},{0,sizeof(t2),t2},{0,sizeof(t3),t3}
    };
    OCT_copy(&PSKID[0],&ETICK); 

    char b1[TLS_MAX_HASH+1],b2[TLS_MAX_HASH+1],b3[TLS_MAX_HASH+1];
    octet BINDERS[3]={
        {0,sizeof(b1),b1},{0,sizeof(b2),b2},{0,sizeof(b3),b3}
    };    

    unsign32 age[3];
    age[0]= age_obfuscator+10000;   // 5 seconds = 5000 milliseconds

// Supported Key Exchange Groups in order of preference
    int nsg=3;
    supportedGroups[0]=X25519;
    supportedGroups[1]=SECP256R1;
    supportedGroups[2]=SECP384R1;

// Generate key pair in favourite group
    GENERATE_KEY_PAIR(&RNG,supportedGroups[0],&SK,&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

// Supported Cipher Suits
    int nsc=2;     
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
  //  ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported

// Extensions
// Supported Cert signing Algorithms - could add more
    int nsa=8;
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
    int alg=supportedGroups[0]; // only sending one key share in favourite group

// Construct vector of public keys

    algs[0]=alg;
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build client Hello extensions
    OCT_clear(&EXT);
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,algs,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    int extra=0;
    extra=addPreSharedKeyExt(&EXT,1,age,PSKID,sha); 

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_0,&CH,nsc,ciphers,&RNG,&CID,&EXT,extra);      
    printf("Client Hello sent\n");

    unihash reshash;
    Hash_Init(sha,&reshash);
    running_hash(&reshash,&CH);  // hash truncated clientHello
    transcript_hash(&HH,&reshash);

    char bnd[TLS_MAX_HASH];
    octet BND={0,sizeof(bnd),bnd};

    //HMAC(MC_SHA2,sha,&BND,sha,&BKR,&HH);

    VERIFY_DATA(sha,&BND,&BKR,&HH);    // ??

    printf("BND= ");OCT_output(&BND);

    //BND.val[5]=BND.val[6]=0x67;
    //printf("BND= ");OCT_output(&BND);

    OCT_copy(&BINDERS[0],&BND);

    char bl[3*TLS_MAX_HASH+3];
    octet BL={0,sizeof(bl),bl};
    printf("Sending Binders\n");

    sendBindersList(sock,&BL,1,BINDERS);

// Process Server Hello

    int pskid;
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK,pskid);
    if (rtn==SH_ALERT)
        printf("Alert received\n");
    printf("serverHello= %d %d ",SH.len,pskid);OCT_output(&SH);

    sleep(5);

    return 0;
}