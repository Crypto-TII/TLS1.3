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

using namespace core;

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
int getServerMessage(octet *RS,int sock,octet *SAK,octet *SAIV,octet *STS,unsign32 &recno,octet *TICK)
{
    int nce,nb,len,te,type,nticks,kur,ptr=0;
    bool fin=false;

    nticks=0; // number of tickets received
    while (1)
    {
        printf("Waiting for Server input \n");
//        if (nticks==2) return 0;
        OCT_clear(RS); ptr=0;
        type=getServerFragment(sock,SAK,SAIV,recno,RS);  // get first fragment to determine type
        if (type==TIME_OUT)
        {
            printf("TIMEOUT\n");
            break;
        }

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
                    printf("Got a ticket\n");
                    parseOctetorPull(sock,TICK,len,RS,ptr,SAK,SAIV,recno);
                        
/*
                    lifetime=parseInt32orPull(sock,RS,ptr,SAK,SAIV,recno);
                    obfuscated_age=parseInt32orPull(sock,RS,ptr,SAK,SAIV,recno);
                    len=parseByteorPull(sock,RS,ptr,SAK,SAIV,recno);
                    //printf("life time t= %d minutes\n",lifetime/60);
                    parseOctetorPull(sock,NONCE,len,RS,ptr,SAK,SAIV,recno);
                    //printf("Nonce = "); OCT_output(NONCE);
                    len=parseInt16orPull(sock,RS,ptr,SAK,SAIV,recno);
                    parseOctetorPull(sock,TICK,len,RS,ptr,SAK,SAIV,recno);
                    //printf("Ticket = "); OCT_output(TICK);
                    te=parseInt16orPull(sock,RS,ptr,SAK,SAIV,recno);
                    ptr+=te;  // skip any ticket extensions
                   // printf("ptr= %d RS->len= %d\n",ptr,RS->len);
*/
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
            printf("Alert received from Server - type= "); OCT_output(RS);  exit(0);
        }
    }

    return 0;
}

// parse out ticket contents. Note that ETICK is the actual ticket to be passed back in a Pre-Shared-Key Extension
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

    char tick[TLS_MAX_TICKET_SIZE];    // A resumption ticket
    octet TICK={0,sizeof(tick),tick};


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

// Client Side Key Exchange 
// Client Capabilities to be advertised

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

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    int alg=supportedGroups[0]; // only sending one key share in favourite group

// Construct vector of public keys

    algs[0]=alg;
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build client Hello extensions
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,algs,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_0,&CH,nsc,ciphers,&RNG,&CID,&EXT,0);      
    printf("Client Hello sent\n");

    int pskid;
// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK,pskid);
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

    GET_EARLY_SECRET(sha,NULL,&ES,NULL,NULL);   // Early Secret

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
        sendClientHello(sock,TLS1_2,&CH,nsc,ciphers,&RNG,&CID,&EXT,0);   
        
        rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK,pskid);
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

    GENERATE_SHARED_SECRET(kex,&SK,&SPK,&SS);
    printf("Shared Secret= ");OCT_output(&SS);


// Hash Transcript Hellos 
    running_hash(&tlshash,&CH);
    transcript_hash(&HH,&tlshash);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
    running_hash(&tlshash,&SH);
    transcript_hash(&HH,&tlshash);
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HS,&CHTS,&SHTS,&HH);

    GET_KEY_AND_IV(cipher_suite,&CHTS,&CHK,&CHIV);
    GET_KEY_AND_IV(cipher_suite,&SHTS,&SHK,&SHIV);
    unsign32 chkrecno=0;  // number of records encrypted with this key
    unsign32 shkrecno=0;

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note CA signature might use old methods, but server will use PSS padding for its signature (or ECC).

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
        //exit(0);
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

// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CHTS,&TH);  
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&CHK,&CHIV,chkrecno,&tlshash,&CHF);   
    transcript_hash(&FH,&tlshash); // hash up to end of Client Finish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&CTS,&STS,NULL,&RMS,&TH,&FH);
    GET_KEY_AND_IV(cipher_suite,&CTS,&CAK,&CAIV);
    GET_KEY_AND_IV(cipher_suite,&STS,&SAK,&SAIV);
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

// Process server responses

    getServerMessage(&RS,sock,&SAK,&SAIV,&STS,sakrecno,&TICK); // .. first extract a ticket

    close(sock);  // After time out, exit and close session
    printf("Connection closed\n");


// Need to keep ticket, nonce, rms
// should add time stamp
/*
    ofstream resumption("resume.sta");

    resumption << TICK.len << endl;
    for (int i=0;i<TICK.len;i++)
        resumption << (unsigned int)(unsigned char)TICK.val[i] << endl;
    resumption << NONCE.len << endl;
    for (int i=0;i<NONCE.len;i++)
        resumption << (unsigned int)(unsigned char)NONCE.val[i] << endl;
    resumption << RMS.len << endl;
    for (int i=0;i<RMS.len;i++)
        resumption << (unsigned int)(unsigned char)RMS.val[i] << endl;

    printf("Stored Ticket= ");OCT_output(&TICK);

    resumption.close();
    return 0;
}


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

*/





/******************* Now attempt Resumption **************************/
/************* given Ticket, and Resumption Master Secret ************/

// parse ticket
    if (TICK.len==0)
    {
        printf("No tickets provided - resumption not possible\n");
        return 0;  // there are no tickets
    }

    printf("\nConnection re-opened - attempting resumption\n");
    printf("Ticket= ");OCT_output(&TICK);

    char psk[TLS_MAX_HASH];
    octet PSK={0,sizeof(psk),psk};
    char bkr[TLS_MAX_HASH];
    octet BKR={0,sizeof(bkr),bkr};
    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce};
    char etick[TLS_MAX_TICKET_SIZE];
    octet ETICK={0,sizeof(etick),etick};
    int lifetime=0;
    unsign32 age_obfuscator=0;

    lifetime=parseTicket(&TICK,&NONCE,&ETICK,age_obfuscator);

    printf("Ticket details\n");
    printf("life time t= %d minutes\n",lifetime/60);
    printf("Age obfuscator = %08x\n",age_obfuscator);
    printf("Nonce = "); OCT_output(&NONCE);
    printf("Ticket = %d ",ETICK.len); OCT_output(&ETICK);

// recover PSK from Resumption Master Secret and Nonce

    sha=RMS.len;   // assume this was hash used to create PSK
    RECOVER_PSK(sha,&RMS,&NONCE,&PSK);  // recover PSK from resumption master secret and ticket nonce
    printf("PSK= "); OCT_output(&PSK);

    GET_EARLY_SECRET(sha,&PSK,&ES,NULL,&BKR);   // compute early secret and Binder Key from PSK
    printf("Binder Key= %d ",sha); OCT_output(&BKR);

// reopen socket

    sock=setclientsock(port,ip);

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
    age[0]= age_obfuscator+10000;   // 10 seconds = 10000 milliseconds

// Supported Key Exchange Groups in order of preference
    nsg=3;
    supportedGroups[0]=X25519;
    supportedGroups[1]=SECP256R1;
    supportedGroups[2]=SECP384R1;

// Generate key pair in favourite group
    GENERATE_KEY_PAIR(&RNG,supportedGroups[0],&SK,&CPK);

    printf("Private key= 0x"); OCT_output(&SK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

// Supported Cipher Suits
    nsc=2;     
    ciphers[0]=TLS_AES_128_GCM_SHA256;
    ciphers[1]=TLS_AES_256_GCM_SHA384;
  //  ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported

// Extensions
// Supported Cert signing Algorithms - could add more
    nsa=8;
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
    tlsVersion=TLS1_3;
    pskMode=PSKWECDHE;
    alg=supportedGroups[0]; // only sending one key share in favourite group

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
    int extra=addPreSharedKeyExt(&EXT,1,age,PSKID,sha); 

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_2,&CH,nsc,ciphers,&RNG,&CID,&EXT,extra);      
    printf("Client Hello sent\n");

    Hash_Init(sha,&tlshash);
    running_hash(&tlshash,&CH);  // hash truncated clientHello
    transcript_hash(&HH,&tlshash);

    char bnd[TLS_MAX_HASH];
    octet BND={0,sizeof(bnd),bnd};

    VERIFY_DATA(sha,&BND,&BKR,&HH);

    printf("BND= ");OCT_output(&BND);

    OCT_copy(&BINDERS[0],&BND);

    char bl[3*TLS_MAX_HASH+3];
    octet BL={0,sizeof(bl),bl};
    printf("Sending Binders\n");

    sendBindersList(sock,&BL,1,BINDERS);
    running_hash(&tlshash,&BL);

// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&CK,&SPK,pskid);
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
            printf("Handshake Retry Request\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); break;  
        case ID_MISMATCH :
            printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case UNRECOGNIZED_EXT :
            printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         case BAD_HELLO :
            printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
         default: sendClientAlert(sock,ILLEGAL_PARAMETER,NULL,NULL,nulrec); exit(0);
        }
    }
    printf("serverHello= %d %d ",SH.len,pskid);OCT_output(&SH);

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
    if (sha==0) exit(0);

    GENERATE_SHARED_SECRET(kex,&SK,&SPK,&SS);
    printf("Shared Secret= ");OCT_output(&SS);

    running_hash(&tlshash,&SH);

    transcript_hash(&HH,&tlshash);
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HS,&CHTS,&SHTS,&HH);

    GET_KEY_AND_IV(cipher_suite,&CHTS,&CHK,&CHIV);
    GET_KEY_AND_IV(cipher_suite,&SHTS,&SHK,&SHIV);
    chkrecno=0;  // number of records encrypted with this key
    shkrecno=0;

// get encrypted extensions
    if (!getServerEncryptedExtensions(&SR,sock,&SHK,&SHIV,shkrecno,&tlshash,&EXT))
    {
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&CHK,&CHIV,chkrecno);
        exit(0);
    }

    transcript_hash(&FH,&tlshash); // hash up to end of Server Verifier
    printf("2. Transcript Hash= "); OCT_output(&FH);

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

// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CHTS,&TH);  
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&CHK,&CHIV,chkrecno,&tlshash,&CHF);   
    transcript_hash(&FH,&tlshash); // hash up to end of Client Finish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&CTS,&STS,NULL,&RMS,&TH,&FH);
    GET_KEY_AND_IV(cipher_suite,&CTS,&CAK,&CAIV);
    GET_KEY_AND_IV(cipher_suite,&STS,&SAK,&SAIV);
    cakrecno=0;  // number of records encrypted with this key
    sakrecno=0;

// Start the Application - send HTML GET command
    OCT_clear(&GET);
    OCT_jstring(&GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  14
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF  2
    OCT_jstring(&GET,(char *)"Host: ");  // 6
    OCT_jstring(&GET,hostname); //OCT_jstring(&PT,(char *)":443");
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // empty line CRLF    
    printf("Sending Application Message\n\n"); OCT_output_string(&GET);

    sendClientMessage(sock,APPLICATION,TLS1_2,&CAK,&CAIV,cakrecno,&GET);

// Process server responses
    getServerMessage(&RS,sock,&SAK,&SAIV,&STS,sakrecno,&TICK); // .. first extract a ticket

    close(sock);  // After time out, exit and close session

    return 0;
} 
