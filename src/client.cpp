// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_hash.cpp tls_cert_chain.cpp tls_parse_octet.cpp tls_client_recv.cpp tls_client_send.cpp tls_tickets.cpp core.a -o client

#include <stdio.h> 
#include <fstream>
#include <string.h> 
#include "tls1_3.h" 
#include "randapi.h"  
#include "x509.h"
#include "tls_keys_calc.h"
#include "tls_hash.h"
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_client_send.h"
#include "tls_tickets.h"

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
// Extract a ticket. K_recv might have been updated.
int processServerMessage(int sock,octet *RS,crypto *K_recv,octet *STS,octet *TICK,struct timeval *time_ticket_received)
{
    int nce,nb,len,te,type,nticks,kur,ptr=0;
    bool fin=false;

    nticks=0; // number of tickets received
    while (1)
    {
        printf("Waiting for Server input \n");
//        if (nticks==2) return 0;
        OCT_clear(RS); ptr=0;
        type=getServerFragment(sock,K_recv,RS);  // get first fragment to determine type
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
                nb=parseByteorPull(sock,RS,ptr,K_recv);
                len=parseInt24orPull(sock,RS,ptr,K_recv);           // message length
                //printf("nb= %x len= %d\n",nb,len);
                switch (nb)
                {
                case TICKET :
                    printf("Got a ticket\n");
              //      if (nticks==1)
              //      { // use first ticket
              //          ptr+=len;
              //      } else {
                        parseOctetorPull(sock,TICK,len,RS,ptr,K_recv);
                        nticks++;
                        gettimeofday(time_ticket_received, NULL);
             //       }
                    if (ptr==RS->len) fin=true; // record finished
                    if (fin) break;
                    continue;
               case KEY_UPDATE :
                    if (len!=1)
                    {
                        printf("Something wrong\n");
                        exit(0);
                    }
                    kur=parseByteorPull(sock,RS,ptr,K_recv);
                    if (kur==0)
                    {
                        UPDATE_KEYS(K_recv,STS);  // reset record number
                        printf("KEYS UPDATED\n");
                    }
                    if (kur==1)
                    {
                        printf("Key update notified - client should do the same (?) \n");
                        UPDATE_KEYS(K_recv,STS);
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
            OCT_chop(RS,NULL,40);   // truncate it to 40 bytes
            OCT_output(RS); 
        }
        if (type==ALERT)
        {
            printf("Alert received from Server - type= "); OCT_output(RS);  exit(0);
        }
    }

    return 0;
}

// send a test message
void client_send(int sock,char *hostname,crypto *K_send,bool early)
{
    char get[256];
    octet GET={0,sizeof(get),get};
// send an HTML GET command
    OCT_clear(&GET);
    OCT_jstring(&GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  14
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF  2
    OCT_jstring(&GET,(char *)"Host: ");  // 6
    OCT_jstring(&GET,hostname); //OCT_jstring(&PT,(char *)":443");
    if (early)
    {
        OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF  2
        OCT_jstring(&GET,(char *)"Early-Data: 1");  // 6
    }
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // CRLF
    OCT_jbyte(&GET,0x0d,1); OCT_jbyte(&GET,0x0a,1);        // empty line CRLF    
    printf("Sending Application Message\n\n"); OCT_output_string(&GET);
    
    sendClientMessage(sock,APPLICATION,TLS1_2,K_send,&GET);
}

int main(int argc, char const *argv[]) 
{ 
    char hostname[TLS_MAX_SERVER_NAME];
    char ip[40];
    int sock, valread, port, rtn; 
    int cipher_suite,cs_hrr,kex,sha;

    crypto K_send, K_recv;    // crypto contexts, sending and receiving
    init_crypto_context(&K_send);
    init_crypto_context(&K_recv);

    char csk[TLS_MAX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octet CSK = {0, sizeof(csk), csk};
    char cpk[TLS_MAX_PUB_KEY_SIZE];      // clients key exchange public key
    octet CPK = {0, sizeof(cpk), cpk};
    char spk[TLS_MAX_PUB_KEY_SIZE];
    octet SPK = {0, sizeof(spk), spk};   // Servers key exchange Public Key
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};      // Shared Secret

    char ch[TLS_MAX_EXTENSIONS+100+TLS_MAX_CIPHER_SUITES*2];  // Client Hello
    octet CH = {0, sizeof(ch), ch};
    char sh[TLS_MAX_SERVER_HELLO];                            // Server Hello
    octet SH = {0, sizeof(sh), sh};
    char ext[TLS_MAX_EXTENSIONS];
    octet EXT={0,sizeof(ext),ext};       // Extensions                  

    char es[TLS_MAX_HASH];               // Early Secret
    octet ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octet HS = {0,sizeof(hs),hs};

    char hh[TLS_MAX_HASH];               
    octet HH={0,sizeof(hh),hh};          // Transcript hashes
    char fh[TLS_MAX_HASH];
    octet FH={0,sizeof(fh),fh};       
    char th[TLS_MAX_HASH];
    octet TH={0,sizeof(th),th};  

    char cts[TLS_MAX_HASH];
    octet CTS = {0,sizeof(cts),cts};   // client traffic secret
    char sts[TLS_MAX_HASH];
    octet STS = {0,sizeof(sts),sts};   // server traffic secret

    char cid[32];                       
    octet CID={0,sizeof(cid),cid};      // Client session ID
    char cook[TLS_MAX_COOKIE];
    octet COOK={0,sizeof(cook),cook};   // Cookie
    char sr[TLS_MAX_SERVER_RESPONSE];
    octet SR={0,sizeof(sr),sr};         // Server response
    char certchain[TLS_MAX_CERTCHAIN_SIZE];           
    octet CERTCHAIN={0,sizeof(certchain),certchain};  // Certificate chain
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octet SCVSIG={0,sizeof(scvsig),scvsig};           // Server's digital signature on transcript
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octet CHF={0,sizeof(chf),chf};                    // client verify
    char cakey[TLS_MAX_PUB_KEY_SIZE];                 
    octet CAKEY = {0, sizeof(cakey), cakey};          // Server's Cert Public Key

    char rms[TLS_MAX_HASH];
    octet RMS = {0,sizeof(rms),rms};   // Resumption master secret
    char cets[TLS_MAX_HASH];           
    octet CETS={0,sizeof(cets),cets};  // Early traffic secret

    char raw[100];
    octet RAW = {0, sizeof(raw), raw}; // Some initial entropy

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
    int kexGroups[TLS_MAX_KEY_SHARES];

    struct timeval time_ticket_received,time_ticket_used;
    bool success,early_data_accepted,ccs_sent=false;

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
        port=4433;
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
    int favourite_group=supportedGroups[0]; // only sending one key share in favourite group

// Generate key pair in favourite group
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);

    printf("Private key= 0x"); OCT_output(&CSK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

// Construct vector of public keys

    kexGroups[0]=favourite_group;
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build client Hello extensions
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,kexGroups,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_0,&CH,nsc,ciphers,&RNG,&CID,&EXT,0);      
    printf("Client Hello sent\n");

    int pskid;
// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&COOK,&SPK,pskid);

// Find cipher-suite chosen by Server
    sha=0;
    for (i=0;i<nsc;i++)
    {
        if (cipher_suite==ciphers[i])
        {
            sha=32; // length of SHA2 hash
            if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
        }
    }
    if (sha==0)
    {
        printf("Cipher_suite not valid %d\n",cipher_suite);
        sendClientAlert(sock,UNEXPECTED_MESSAGE,NULL); exit(0);
    }


    GET_EARLY_SECRET(sha,NULL,&ES,NULL,NULL);   // Early Secret

// Init Transcript Hash
// For Transcript hash must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;
    Hash_Init(sha,&tlshash);    

// HelloRetryRequest ?
    if (rtn==HS_RETRY)
    {
        if (kex==favourite_group)
        { // its the same one I chose !?
            printf("No change as result of HRR\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
        }
        printf("Server HelloRetryRequest= %d ",SH.len); OCT_output(&SH);
        running_syn_hash(&CH,&tlshash); // RFC 8446 section 4.4.1
        running_hash(&SH,&tlshash);   // Hash of HelloRetryRequest

// Fix clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_clear(&EXT);
        addServerNameExt(&EXT,hostname);
        addSupportedGroupsExt(&EXT,nsg,supportedGroups);
        addSigAlgsExt(&EXT,nsa,sigAlgs);

// generate new key pair in new server selected group 
        favourite_group=kex;
        GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);
        OCT_copy(&MCPK[0],&CPK);   // Public Key Share in new group
        kexGroups[0]=favourite_group; addKeyShareExt(&EXT,1,kexGroups,MCPK);

        addPSKExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);

        sendCCCS(sock);  // send Client Cipher Change
        ccs_sent=true;
// create and send new Client Hello Octet
        sendClientHello(sock,TLS1_2,&CH,nsc,ciphers,&RNG,&CID,&EXT,0);   
        rtn=getServerHello(sock,&SH,cs_hrr,kex,&CID,&COOK,&SPK,pskid);
        if (rtn==HS_RETRY)
        {
            printf("A second Handshake Retry Request?\n"); sendClientAlert(sock,UNEXPECTED_MESSAGE,NULL); exit(0);
        }
        if (cs_hrr!=cipher_suite)
        {
            printf("Server selected different cipher suite\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
        }
    }

    if (rtn!=0)
    { // respond to bad serverHello
        unsign32 nulrec=0;
        switch (rtn )
        {
        case SH_ALERT :
            printf("Received an alert - "); OCT_output(&SH); exit(0);
        case NOT_TLS1_3 :
            printf("Site does not support TLS 1.3\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
        case ID_MISMATCH :
            printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
         case UNRECOGNIZED_EXT :
            printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
         case BAD_HELLO :
            printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
         default: sendClientAlert(sock,ILLEGAL_PARAMETER,NULL); exit(0);
        }
    }

    printf("Server Hello= %d ",SH.len); OCT_output(&SH);

    GENERATE_SHARED_SECRET(kex,&CSK,&SPK,&SS);
    printf("Shared Secret= ");OCT_output(&SS);

// Hash Transcript Hellos 
    running_hash(&CH,&tlshash);
    running_hash(&SH,&tlshash);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
    transcript_hash(&tlshash,&HH);              // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note CA signature might use old methods, but server will use PSS padding for its signature (or ECC).

// get encrypted extensions
    if (!getServerEncryptedExtensions(sock,&SR,&K_recv,&tlshash,early_data_accepted))
    {
        printf("Unexpected message - aborting\n");
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&K_send);
        exit(0);
    }

// get certificate chain
    if (!getServerCertificateChain(sock,&SR,&K_recv,&tlshash,&CERTCHAIN))
    {
        printf("Unexpected message - aborting\n");
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&K_send);
        exit(0);
    }
    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain
    printf("1. Transcript Hash= "); OCT_output(&HH);

// check certificate chain, and extract Server Cert Public Key
    if (CHECK_CERT_CHAIN(&CERTCHAIN,&CAKEY))
        printf("Certificate Chain is valid\n");
    else
    {
        printf("Certificate is NOT valid\n");
        sendClientAlert(sock,BAD_CERTIFICATE,&K_send);
        exit(0);
    }

// get verifier
    int sigalg=getServerCertVerify(sock,&SR,&K_recv,&tlshash,&SCVSIG);
    if (sigalg<=0)
    {
        printf("sigalg is wrong\n");
        sendClientAlert(sock,DECRYPT_ERROR,&K_send);
        exit(0);
    }
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
    printf("2. Transcript Hash= "); OCT_output(&FH);
    
    printf("Signature Algorithm= %04x\n",sigalg);
    printf("Server Certificate Signature= %d ",SCVSIG.len); OCT_output(&SCVSIG);

    if (IS_SERVER_CERT_VERIFY(sigalg,&SCVSIG,&HH,&CAKEY))
        printf("Server Cert Verification OK\n");
    else
    {
        printf("Server Cert Verification failed\n");
        sendClientAlert(sock,DECRYPT_ERROR,&K_send);
        exit(0);
    }
// get Server Finished
    if (!getServerFinished(sock,&SR,&K_recv,&tlshash,&FIN))
    {
        printf("Server Finish incorrect\n");
        sendClientAlert(sock,DECRYPT_ERROR,&K_send);
        exit(0);
    }
    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

    printf("3. Transcript Hash= "); OCT_output(&TH);

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        printf("Server Data is verified\n");
    else
    {
        printf("Server Data is NOT verified\n");
        sendClientAlert(sock,DECRYPT_ERROR,&K_send);
        exit(0);
    }

    if (!ccs_sent)
        sendCCCS(sock);  // send Client Cipher Change

// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&K_send,&tlshash,&CHF);   
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&TH,&FH,&CTS,&STS,NULL,&RMS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

// Start the Application - send HTML GET command

    client_send(sock,hostname,&K_send,false);

// Process server responses

    processServerMessage(sock,&SR,&K_recv,&STS,&TICK,&time_ticket_received); // .. first extract a ticket

    close(sock);  // After time out, exit and close session
    printf("Connection closed\n");






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
    octet PSK={0,sizeof(psk),psk};   // Pre-shared key
    char bkr[TLS_MAX_HASH];
    octet BKR={0,sizeof(bkr),bkr};   // Binder secret
    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce}; // ticket nonce
    char etick[TLS_MAX_TICKET_SIZE];
    octet ETICK={0,sizeof(etick),etick}; // ticket
    int lifetime=0;
    unsign32 age_obfuscator=0;
    unsign32 max_early_data=0;
    bool have_early_data=true;

    lifetime=parseTicket(&TICK,&NONCE,&ETICK,age_obfuscator,max_early_data);

    printf("\nTicket details\n");
    printf("life time t= %d minutes\n",lifetime/60);
    printf("Age obfuscator = %08x\n",age_obfuscator);
    printf("Nonce = "); OCT_output(&NONCE);
    printf("Ticket = %d ",ETICK.len); OCT_output(&ETICK);
    printf("max_early_data = %d\n\n",max_early_data); 

    if (max_early_data==0)
        have_early_data=false;

// recover PSK from Resumption Master Secret and Nonce

    sha=RMS.len;   // assume this was hash used to create PSK
    RECOVER_PSK(sha,&RMS,&NONCE,&PSK);  // recover PSK from resumption master secret and ticket nonce
    printf("PSK= "); OCT_output(&PSK);

    GET_EARLY_SECRET(sha,&PSK,&ES,NULL,&BKR);   // compute early secret and Binder Key from PSK
    printf("Binder Key= %d ",sha); OCT_output(&BKR);
    printf("Early Secret= "); OCT_output(&ES);

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

// Generate key pair in favourite group - use same favourite group that worked before - should be no HRR
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);

    printf("Private key= 0x"); OCT_output(&CSK); 
    printf("Client Public key= 0x"); OCT_output(&CPK); 

// Prepare for extensions
    tlsVersion=TLS1_3;
    pskMode=PSKWECDHE;

// Construct vector of public keys
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build client Hello extensions
    OCT_clear(&EXT);
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,nsg,supportedGroups);
    addSigAlgsExt(&EXT,nsa,sigAlgs);
    addKeyShareExt(&EXT,1,kexGroups,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    if (have_early_data)
        addEarlyDataExt(&EXT);                                          // try sending early data if allowed

    unsign32 age[3];
    gettimeofday(&time_ticket_used, NULL);
    age[0]= milliseconds(time_ticket_received,time_ticket_used);   // age of ticket in milliseconds
    printf("Ticket age= %d\n",age[0]);
    age[0]+=age_obfuscator;
    printf("obfuscated age = %x\n",age[0]);
    int extra=addPreSharedKeyExt(&EXT,1,age,PSKID,sha); 


    if (have_early_data)
        sendCCCS(sock);

// create and send Client Hello Octet
    sendClientHello(sock,TLS1_2,&CH,nsc,ciphers,&RNG,&CID,&EXT,extra);      
    printf("Truncated Client Hello sent\n");

    Hash_Init(sha,&tlshash);
    running_hash(&CH,&tlshash);  
    transcript_hash(&tlshash,&HH); // hash of truncated clientHello

    char bnd[TLS_MAX_HASH];
    octet BND={0,sizeof(bnd),bnd};

    VERIFY_DATA(sha,&BND,&BKR,&HH);

    printf("BND= ");OCT_output(&BND);

    OCT_copy(&BINDERS[0],&BND);

    char bl[3*TLS_MAX_HASH+3];
    octet BL={0,sizeof(bl),bl};

    printf("Sending Binders\n");
    sendBindersList(sock,&BL,1,BINDERS);
    running_hash(&BL,&tlshash);
    transcript_hash(&tlshash,&HH);  // hash of full clientHello

    GET_LATER_SECRETS(sha,&ES,&HH,&CETS,NULL); // Get Client Early Traffic Secret
    printf("Client Early Traffic Secret= "); OCT_output(&CETS);
    GET_KEY_AND_IV(cipher_suite,&CETS,&K_send);  // Set Client K_send to early data keys   // ? which cipher suite?

// send some early data ??                                          // ******************
    if (have_early_data)
    {
        printf("Sending some early data\n");
        client_send(sock,hostname,&K_send,true);
    }
// Process Server Hello
    rtn=getServerHello(sock,&SH,cipher_suite,kex,&CID,&COOK,&SPK,pskid);
    if (rtn!=0)
    {
        switch (rtn )
        {
        case SH_ALERT :
            printf("Received an alert - %d ",SH.len); OCT_output(&SH); exit(0);
        case NOT_TLS1_3 :
            printf("Site does not support TLS 1.3\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); exit(0);
        case HS_RETRY :
            printf("Handshake Retry Request\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); break;  
        case ID_MISMATCH :
            printf("Identities do not match\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); exit(0);
         case UNRECOGNIZED_EXT :
            printf("Received an unrecognized extension\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); exit(0);
         case BAD_HELLO :
            printf("Malformed serverHello\n"); sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); exit(0);
         default: sendClientAlert(sock,ILLEGAL_PARAMETER,&K_send); exit(0);
        }
    }
    printf("serverHello= %d %d ",SH.len,pskid);OCT_output(&SH);
 
    if (pskid<0)
    {
        printf("Preshared key rejected by server\n");
        exit(0);
    }

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
    if (sha==0) exit(0);

    GENERATE_SHARED_SECRET(kex,&CSK,&SPK,&SS);
    printf("Shared Secret= ");OCT_output(&SS);

    running_hash(&SH,&tlshash);
    transcript_hash(&tlshash,&HH);       // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS); 
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

// get encrypted extensions
    success=getServerEncryptedExtensions(sock,&SR,&K_recv,&tlshash,early_data_accepted);
    if (success)
    {
        if (early_data_accepted)
            printf("Early Data Accepted\n");
        transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension
        printf("2. Transcript Hash= "); OCT_output(&FH);
        success=getServerFinished(sock,&SR,&K_recv,&tlshash,&FIN);   // Finished
        printf("SR.len= %d\n",SR.len);
    } else {
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&K_send);
        exit(0);
    }

// Now send End of Early Data, encrypted with 0-RTT keys
    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (early_data_accepted)
    {
        printf("Send End of Early Data \n");
        sendEndOfEarlyData(sock,&K_send,&tlshash);                 // Should only be sent if server has accepted Early data - see encrypted extensions!
    }

    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
    printf("3. Transcript Hash= "); OCT_output(&TH);

// Switch to handshake keys
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);

    if (!success)
    {
        printf("Client Aborts\n");
        sendClientAlert(sock,UNEXPECTED_MESSAGE,&K_send);
        exit(0);
    }

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        printf("Server Data is verified\n");
    else
        printf("Server Data is NOT verified\n");

//    sendCCCS(sock);  // send Client Cipher Change

// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    printf("Client Verify Data= "); OCT_output(&CHF);
    sendClientVerify(sock,&K_send,&tlshash,&CHF);   
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&HH,NULL,&CTS,&STS,NULL,NULL);  // should really be TH
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

// Start the Application - send HTML GET command
    if (!early_data_accepted)
        client_send(sock,hostname,&K_send,false);

// Process server responses
    processServerMessage(sock,&SR,&K_recv,&STS,&TICK,&time_ticket_received); // .. first extract a ticket
    close(sock);  // After time out, exit and close session

    return 0;
} 
