// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_hash.cpp tls_scv.cpp tls_cert_chain.cpp tls_parse_octet.cpp tls_client_recv.cpp tls_client_send.cpp core.a -o client

#include <stdio.h> 
#include <string.h> 
#include <time.h>
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

using namespace core;

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

// parse Server records received after handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
int getServerMessage(octet *RS,int sock,octet *SAK,octet *SAIV,octet *STS,unsign32 &recno)
{
    int lt,age,nce,nb,len,te,type,nticks,kur,ptr=0;
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
        type=getServerFragment(sock,SAK,SAIV,recno,RS);  // get first fragment to determine type
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
                    printf("life time t= %d age obfuscator = %d\n",lt,age);
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
               case KEY_UPDATE :
                    if (len!=1)
                    {
                        printf("Something wrong\n");
                        exit(0);
                    }
                    kur=parseByteorPull(sock,RS,ptr,SAK,SAIV,recno);
                    if (kur==0)
                    {
                        recno=UPDATE_KEYS(SAK,SAIV,STS);  // reset record number
                        printf("KEYS UPDATED\n");
                    }
                    if (kur==1)
                    {
                        printf("Key update notified - client should do the same (?) \n");
                        recno=UPDATE_KEYS(SAK,SAIV,STS);
                        printf("KEYS UPDATED\n");
                    }
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
        }
        if (type==APPLICATION)
        {
            printf("Application data (truncated HTML) = ");
            OCT_chop(RS,NULL,40);   // truncate it to 20 bytes
            OCT_output(RS); 
        }
        if (type==ALERT)
        {
            printf("Alert received from Server - type= "); OCT_output(RS); exit(0);
        }
    }

    return 0;
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

    char raw[100];
    octet RAW = {0, sizeof(raw), raw}; // Some initial entropy

    int i, res;
    unsigned long ran;
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

// Client Side Key Exchange 
// Client Capabilities to be advertised

// Supported Key Exchange Groups in order of preference
    int nsg=3;
    int supportedGroups[TLS_MAX_SUPPORTED_GROUPS];
    supportedGroups[0]=X25519;
    supportedGroups[1]=SECP256R1;
    supportedGroups[2]=SECP384R1;

// Generate key pair in favourite group
    GENERATE_KEY_PAIR(&RNG,supportedGroups[0],&SK,&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

// Supported Cipher Suits
    int nsc=2;     
    int ciphers[TLS_MAX_CIPHER_SUITES];
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
  //  ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported

// Supported Cert signing Algorithms - could add more
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
    int alg=supportedGroups[0]; // only sending one key share in favourite group

// could be a vector of public keys
    int algs[TLS_MAX_KEY_SHARES];
    algs[0]=alg;
    char m1[TLS_MAX_PUB_KEY_SIZE],m2[TLS_MAX_PUB_KEY_SIZE],m3[TLS_MAX_PUB_KEY_SIZE];
    octet MCPK[3]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3}
    };

    OCT_copy(&MCPK[0],&CPK);   // Public Key Share

// Client Hello
    char ext[TLS_MAX_EXTENSIONS];
    octet EXT={0,sizeof(ext),ext};

// build client Hello extensions
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,algs,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_0,&CH,nsc,ciphers,&RNG,&CID,&EXT);      
    printf("Client Hello sent\n");

// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK);
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
            printf("Handshake Retry Request\n"); break;  
        case ID_MISMATCH :
            printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case UNRECOGNIZED_EXT :
            printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case BAD_HELLO :
            printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         default: sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
        }
    }

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
    if (sha==0) exit(0);

// Init Transcript Hash
// For Transcript hash must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;
    Hash_Init(sha,&tlshash);    

// HelloRetryRequest ?
    if (rtn==HS_RETRY)
    {
        printf("Server HelloRetryRequest= %d ",SH.len); OCT_output(&SH);
        running_syn_hash(&tlshash,&CH); // RFC 8446 section 4.4.1
        running_hash(&tlshash,&SH);   // Hash of HelloRetryRequest

// Fix clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_clear(&EXT);
        addServerNameExt(&EXT,hostname);
        addSupportedGroupsExt(&EXT,nsg,supportedGroups);
        addSigAlgsExt(&EXT,nsa,sigAlgs);

// generate new key pair in server selected group "kex"
        GENERATE_KEY_PAIR(&RNG,kex,&SK,&CPK);
        OCT_copy(&MCPK[0],&CPK);   // Public Key Share
        algs[0]=kex; addKeyShareExt(&EXT,1,algs,MCPK);

        addPSKExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        if (CK.len!=0)
            addCookieExt(&EXT,&CK);

// create and send new Client Hello Octet
        sendClientHello(sock,TLS1_2,&CH,nsc,ciphers,&RNG,&CID,&EXT);   
        
        rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK);
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
                printf("Handshake Retry Request\n"); sendClientAlert(sock,UNEXPECTED_MESSAGE,NULL,NULL,nulrec); exit(0);     
            case ID_MISMATCH :
                printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
            case UNRECOGNIZED_EXT :
                printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
            case BAD_HELLO :
                printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
            default: sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
            }
        }
    }

    printf("Server Hello= %d ",SH.len); OCT_output(&SH);

// Hash Transcript Hellos 
    running_hash(&tlshash,&CH);
    running_hash(&tlshash,&SH);
    transcript_hash(&HH,&tlshash);

    GENERATE_SHARED_SECRET(kex,&SK,&SPK,&SS);
    printf("Shared Secret= ");OCT_output(&SS);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
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
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&CHK,&CHIV,chkrecno);
        exit(0);
    }
// get certificate chain
    if (!getServerCertificateChain(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&CERTCHAIN))
    {
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    transcript_hash(&HH,&tlshash); // hash up to end of Server cert
    printf("1. Transcript Hash= "); OCT_output(&HH);

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
        printf("sigalg is wrong\n");
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    transcript_hash(&FH,&tlshash); // hash up to end of Server Verifier
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
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&CHK,&CHIV,chkrecno);
        exit(0);
    }
    transcript_hash(&TH,&tlshash); // hash up to end of Server Finish

    printf("3. Transcript Hash= "); OCT_output(&TH);

    if (IS_VERIFY_DATA(sha,&FIN,&SHTS,&FH))
        printf("Server Data is verified\n");
    else
        printf("Server Data is NOT verified\n");

    sendCCCS(sock);  // send Client Cipher Change

    char chf[TLS_MAX_HASH];   // client verify
    octet CHF={0,sizeof(chf),chf};

// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CHTS,&TH);  
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&CHK,&CHIV,chkrecno,&CHF);   

// calculate traffic and application keys
    GET_APPLICATION_SECRETS(cipher_suite,&CAK,&CAIV,&SAK,&SAIV,&CTS,&STS,&TH,&HS);
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

// Process server responses
    getServerMessage(&RS,sock,&SAK,&SAIV,&STS,sakrecno); // .. first extract tickets

    return 0;
} 
