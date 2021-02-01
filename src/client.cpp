// Client side C/C++ program to demonstrate TLS1.3 
// g++ -O2 client.cpp tls_keys_calc.cpp tls_sockets.cpp tls_cert_chain.cpp  tls_client_recv.cpp tls_client_send.cpp tls_tickets.cpp tls_logger.cpp tls_cacerts.cpp core.a -o client

#include <stdio.h> 
#include <fstream>
#include <string.h> 
#include "tls1_3.h" 
#include "randapi.h"  
#include "x509.h"
#include "tls_keys_calc.h"
#include "tls_cert_chain.h"
#include "tls_client_recv.h"
#include "tls_client_send.h"
#include "tls_tickets.h"
#include "tls_logger.h"

using namespace core;

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// Extract a ticket. K_recv might be updated.

// all terminal output redirected here
void myprintf(char *s)
{
#ifdef CORE_ARDUINO
    char line[80];
    sprintf(line, "%s", s);
    Serial.print(my_data);
#else
    printf("%s",s);
#endif
}

int processServerMessage(FILE *fp,Socket &client,octet *IO,crypto *K_recv,octet *STS,octet *TICK,struct timeval *time_ticket_received)
{
    ret r;
    int nce,nb,len,te,type,nticks,kur,ptr=0;
    bool fin=false;

    OCT_clear(TICK);
    nticks=0; // number of tickets received
    while (1)
    {
        myprintf((char *)"Waiting for Server input \n");
        if (fp!=stdout) logger(fp,(char *)"Waiting for Server input \n",NULL,0,NULL);

        OCT_clear(IO); ptr=0;
        type=getServerFragment(client,K_recv,IO);  // get first fragment to determine type

        if (type<0)
            return type;   // its an error

        if (type==TIME_OUT)
        {
            myprintf((char *)"TIME_OUT\n");
            if (fp!=stdout) logger(fp,(char *)"TIME_OUT\n",NULL,0,NULL);
            break;
        }

        if (type==HSHAKE)
        {
            while (1)
            {
                r=parseByteorPull(client,IO,ptr,K_recv); nb=r.val; if (r.err) return r.err;
                r=parseInt24orPull(client,IO,ptr,K_recv); len=r.val; if (r.err) return r.err;   // message length
                switch (nb)
                {
                case TICKET :   // keep last ticket
                    myprintf((char *)"Got a ticket\n");
                    if (fp!=stdout) logger(fp,(char *)"Got a ticket\n",NULL,0,NULL);
                    r=parseOctetorPull(client,TICK,len,IO,ptr,K_recv);
                    nticks++;
                    gettimeofday(time_ticket_received, NULL);
                    if (ptr==IO->len) fin=true; // record finished
                    if (fin) break;
                    continue;
               case KEY_UPDATE :
                    if (len!=1)
                    {
                        myprintf((char *)"Something wrong\n");
                        if (fp!=stdout) logger(fp,(char *)"Something wrong\n",NULL,0,NULL);
                        return 0;
                    }
                    r=parseByteorPull(client,IO,ptr,K_recv); kur=r.val; if (r.err) break;
                    if (kur==0)
                    {
                        UPDATE_KEYS(K_recv,STS);  // reset record number
                        myprintf((char *)"KEYS UPDATED\n");
                        if (fp!=stdout) logger(fp,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (kur==1)
                    {
                        myprintf((char *)"Key update notified - client should do the same (?) \n");
                        if (fp!=stdout) logger(fp,(char *)"Key update notified - client should do the same (?) \n",NULL,0,NULL);
                        UPDATE_KEYS(K_recv,STS);
                        myprintf((char *)"KEYS UPDATED\n");
                        if (fp!=stdout) logger(fp,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (ptr==IO->len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
                    myprintf((char *)"Unsupported Handshake message type \n");
                    if (fp!=stdout) logger(fp,(char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
                    fin=true;
                    break;            
                }
                if (r.err) return r.err;
                if (fin) break;
            }
        }
        if (type==APPLICATION)
        {
            myprintf((char *)"Application data (truncated HTML) = ");
            OCT_chop(IO,NULL,40);   // truncate it to 40 bytes
            OCT_output(IO); 
            if (fp!=stdout) logger(fp,(char *)"Application data (truncated HTML) = ",NULL,0,IO);
            return 0;
        }
        if (type==ALERT)
        {
            myprintf((char *)"Alert received from Server - type= "); OCT_output(IO);  
            if (fp!=stdout) logger(fp,(char *)"Alert received from Server - type= ",NULL,0,IO);
            return 0;
        }
    }
    return 0;
}

void make_client_message(octet *GET,char *hostname,bool early)
{
// Construct an HTML GET command
    OCT_clear(GET);
    OCT_jstring(GET,(char *)"GET / HTTP/1.1"); // standard HTTP GET command  
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);      
    OCT_jstring(GET,(char *)"Host: ");  
    OCT_jstring(GET,hostname); //OCT_jstring(&PT,(char *)":443");
//    if (early)
//    {
//        OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);        // CRLF  2
//        OCT_jstring(GET,(char *)"Early-Data: 1");  // Is this needed???
//    }
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);        // CRLF
    OCT_jbyte(GET,0x0d,1); OCT_jbyte(GET,0x0a,1);        // empty line CRLF    
}

// send a GET message post-handshake
void client_send(FILE *fp,Socket &client,char *hostname,crypto *K_send,bool early,octet *IO)
{
    char get[256];
    octet GET={0,sizeof(get),get};

    make_client_message(&GET,hostname,early);

    myprintf((char *)"Sending Application Message\n\n"); OCT_output_string(&GET);
    if (fp!=stdout)
        logger(fp,(char *)"Sending Application Message\n\n",GET.val,0,NULL);
    
    sendClientMessage(client,APPLICATION,TLS1_2,K_send,&GET,IO);
}

// TLS1.3 full handshake
// fp - logging file
// client - socket connection
// hostname - website for connection
// RNG - Random Number generator
// favourite group - may be changed on handshake retry
// Capabilities - the supported crypto primitives
// RMS - returned Resumption Master secret
// TICK - returned resumption ticket
// time_ticket_received - Time above Ticket was received

int TLS13_full(FILE *fp,Socket &client,char *hostname,csprng &RNG,int &favourite_group,capabilities &CPB,octet &RMS,ticket &T)
{
    int i,rtn,pskid;
    int cipher_suite,cs_hrr,kex,sha;
    int kexGroups[TLS_MAX_KEY_SHARES];
    bool early_data_accepted,ccs_sent=false;
    bool resumption_required=false;

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

    char io[TLS_MAX_IO_SIZE];
    octet IO={0,sizeof(io),io};         // IO buffer - all messages come via this octet   --- BIG

    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octet SCVSIG={0,sizeof(scvsig),scvsig};           // Server's digital signature on transcript
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octet CHF={0,sizeof(chf),chf};                    // client verify
    char cakey[TLS_MAX_PUB_KEY_SIZE];                 
    octet CAKEY = {0, sizeof(cakey), cakey};          // Server's Cert Public Key
    char cets[TLS_MAX_HASH];           
    octet CETS={0,sizeof(cets),cets};  // Early traffic secret

// choice of up to 3 public keys for key exchange
    char m1[TLS_MAX_PUB_KEY_SIZE],m2[TLS_MAX_PUB_KEY_SIZE],m3[TLS_MAX_PUB_KEY_SIZE];
    octet MCPK[3]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3}
    };

    char tick[TLS_MAX_TICKET_SIZE];    // A resumption ticket
    octet TICK={0,sizeof(tick),tick};

    struct timeval time_ticket_received;

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    favourite_group=CPB.supportedGroups[0]; // only sending one key share in favourite group

//
// Generate key pair in favourite group
//
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);

    logger(fp,(char *)"Private key= ",NULL,0,&CSK);
    logger(fp,(char *)"Client Public key= ",NULL,0,&CPK);

// Construct vector of public keys
    kexGroups[0]=favourite_group;
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build our preferred mix of client Hello extensions, based on our capabililities
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
    addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
    addKeyShareExt(&EXT,1,kexGroups,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);   // ask for smaller max fragment length of 4096 - server may not agree - but no harm in asking

// create and send Client Hello Octet
    sendClientHello(client,TLS1_0,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,0,&IO);   
    logger(fp,(char *)"Client to Server -> ",NULL,0,&IO); 
    logger(fp,(char *)"Client Hello sent\n",NULL,0,NULL);

// Process Server Hello response
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&SPK,pskid);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {  
        sendClientAlert(client,alert_from_cause(rtn),NULL,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

// Find cipher-suite chosen by Server
    sha=0;
    for (i=0;i<CPB.nsc;i++)
    {
        if (cipher_suite==CPB.ciphers[i])
        {
            sha=32; // length of SHA256 hash
            if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48; // length of SHA384
        }
    }
    if (sha==0)
    {
        logger(fp,(char *)"Cipher_suite not valid ",(char *)"%x",cipher_suite,NULL);
        sendClientAlert(client,UNEXPECTED_MESSAGE,NULL,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);     
        return 0;
    }
    logger(fp,(char *)"Cipher suite= ",(char *)"%x",cipher_suite,NULL);

    GET_EARLY_SECRET(sha,NULL,&ES,NULL,NULL);   // Early Secret

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
// which could be SHA256 or SHA384
    unihash tlshash;
    Hash_Init(sha,&tlshash);    

// Did serverHello ask for HelloRetryRequest?
    if (rtn==HANDSHAKE_RETRY)
    {
        if (kex==favourite_group)
        { // its the same one I chose !?
            logger(fp,(char *)"No change as result of HRR\n",NULL,0,NULL); 
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL,&IO);
            logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);     
            return 0;
        }
        logger(fp,(char *)"Server HelloRetryRequest= ",NULL,0,&IO);
        running_syn_hash(&CH,&tlshash); // RFC 8446 section 4.4.1
        running_hash(&IO,&tlshash);     // Hash of HelloRetryRequest

// Fix clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_clear(&EXT);
        addServerNameExt(&EXT,hostname);
        addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
        addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);

// generate new key pair in new server selected group 
        favourite_group=kex;
        GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);
        OCT_copy(&MCPK[0],&CPK);   // Public Key Share in new group
        kexGroups[0]=favourite_group; 
        addKeyShareExt(&EXT,1,kexGroups,MCPK);
        addPSKExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        addMFLExt(&EXT,4);                      // ask for max fragment length of 4096
        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR

        sendCCCS(client);  // send Client Cipher Change
        ccs_sent=true;

// create and send new Client Hello Octet
        sendClientHello(client,TLS1_2,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,0,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        rtn=getServerHello(client,&IO,cs_hrr,kex,&CID,&COOK,&SPK,pskid);
        if (rtn==HANDSHAKE_RETRY)
        { // only one retry allowed
            logger(fp,(char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
            sendClientAlert(client,UNEXPECTED_MESSAGE,NULL,&IO);
            logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
            return 0;
        }
        if (cs_hrr!=cipher_suite)
        { // Server cannot change cipher_suite at this stage
            logger(fp,(char *)"Server selected different cipher suite\n",NULL,0,NULL); 
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL,&IO); 
            logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
            return 0;
        }
        resumption_required=true;
    }

    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {  
        sendClientAlert(client,alert_from_cause(rtn),NULL,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    logger(fp,(char *)"Server Hello= ",NULL,0,&IO); 
    logServerHello(fp,cipher_suite,kex,pskid,&SPK,&COOK);

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    GENERATE_SHARED_SECRET(kex,&CSK,&SPK,&SS);
    logger(fp,(char *)"Shared Secret= ",NULL,0,&SS);

// Hash Transcript Hellos 
    running_hash(&CH,&tlshash);
    running_hash(&IO,&tlshash);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
    transcript_hash(&tlshash,&HH);              // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

    logger(fp,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(fp,(char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger(fp,(char *)"Server handshake traffic secret= ",NULL,0,&STS);

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).

// 1. get encrypted extensions
    OCT_clear(&IO);
    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,early_data_accepted);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;
    logger(fp,(char *)"Encrypted Extensions Processed\n ",NULL,0,NULL);

// 2. get certificate chain, check it, get Server public key
    rtn=getCheckServerCertificateChain(fp,client,&IO,&K_recv,&tlshash,&CAKEY);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;
    logger(fp,(char *)"Certificate Chain is valid\n",NULL,0,NULL);

    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain
    logger(fp,(char *)"Transcript Hash= ",NULL,0,&HH); 

// 3. get verifier signature
    int sigalg;
    rtn=getServerCertVerify(client,&IO,&K_recv,&tlshash,&SCVSIG,sigalg);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
    logger(fp,(char *)"Transcript Hash= ",NULL,0,&FH);
    logger(fp,(char *)"Signature Algorithm= ",(char *)"%04x",sigalg,NULL);
    logger(fp,(char *)"Server Certificate Signature= ",NULL,0,&SCVSIG);

    if (IS_SERVER_CERT_VERIFY(fp,sigalg,&SCVSIG,&HH,&CAKEY))
        logger(fp,(char *)"Server Cert Verification OK\n",NULL,0,NULL);
    else
    {
        logger(fp,(char *)"Server Cert Verification failed\n",NULL,0,NULL);
        sendClientAlert(client,DECRYPT_ERROR,&K_send,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }

// 4. get Server Finished
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_recv,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

    logger(fp,(char *)"Transcript Hash= ",NULL,0,&TH);

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        logger(fp,(char *)"Server Data is verified\n",NULL,0,NULL);
    else
    {
        logger(fp,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        sendClientAlert(client,DECRYPT_ERROR,&K_send,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }

    if (!ccs_sent)
        sendCCCS(client);  // send Client Cipher Change (if not already sent)

// create client verify data
// .... and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    logger(fp,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    sendClientVerify(client,&K_send,&tlshash,&CHF,&IO);   
    logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&TH,&FH,&CTS,&STS,NULL,&RMS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);
    logger(fp,(char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger(fp,(char *)"Server application traffic secret= ",NULL,0,&STS);


// Start the Application - send HTML GET command
    client_send(fp,client,hostname,&K_send,false,&IO);

// Process server responses
    rtn=processServerMessage(fp,client,&IO,&K_recv,&STS,&TICK,&time_ticket_received); 
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }

    init_ticket_context(&T,time_ticket_received); // initialise and time-stamp a new ticket
    parseTicket(&TICK,&T);  // extract into ticket structure, and keep for later use

    if (resumption_required) return 2;
    return 1;
}

// TLS1.3 resumption handshake
// fp - logging file
// client - socket connection
// hostname - website for reconnection
// RNG - Random Number generator
// favourite group - as selected on previous connection
// Capabilities - the supported crypto primitives
// RMS - Resumption Master secret from previous session
// T - Resumption ticket
int TLS13_resume(FILE *fp,Socket &client,char *hostname,csprng &RNG,int favourite_group,capabilities &CPB,octet &RMS,ticket &T)
{
    int sha,rtn,kex,cipher_suite,pskid;
    int kexGroups[TLS_MAX_KEY_SHARES];
    bool early_data_accepted;
    kexGroups[0]=favourite_group;

    char es[TLS_MAX_HASH];               // Early Secret
    octet ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octet HS = {0,sizeof(hs),hs};

    crypto K_send, K_recv;              // crypto contexts, sending and receiving
    init_crypto_context(&K_send);
    init_crypto_context(&K_recv);

    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};      // Shared Secret

    char csk[TLS_MAX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octet CSK = {0, sizeof(csk), csk};
    char cpk[TLS_MAX_PUB_KEY_SIZE];      // clients key exchange public key
    octet CPK = {0, sizeof(cpk), cpk};
    char spk[TLS_MAX_PUB_KEY_SIZE];
    octet SPK = {0, sizeof(spk), spk};   // Servers key exchange Public Key

    char ch[TLS_MAX_EXTENSIONS+100+TLS_MAX_CIPHER_SUITES*2];  // Client Hello
    octet CH = {0, sizeof(ch), ch};
    char ext[TLS_MAX_EXTENSIONS];
    octet EXT={0,sizeof(ext),ext};       // Extensions  

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

    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octet CHF={0,sizeof(chf),chf};                    // client verify
    char cakey[TLS_MAX_PUB_KEY_SIZE];                 
    octet CAKEY = {0, sizeof(cakey), cakey};          // Server's Cert Public Key
    char cets[TLS_MAX_HASH];           
    octet CETS={0,sizeof(cets),cets};  // Early traffic secret
    char cid[32];                       
    octet CID={0,sizeof(cid),cid};      // Client session ID

    char cook[TLS_MAX_COOKIE];
    octet COOK={0,sizeof(cook),cook};   // Cookie
    char io[TLS_MAX_IO_SIZE];
    octet IO={0,sizeof(io),io};         // IO buffer - all messages come via this octet   --- BIG

// choice of up to 3 public keys for key exchange
    char m1[TLS_MAX_PUB_KEY_SIZE],m2[TLS_MAX_PUB_KEY_SIZE],m3[TLS_MAX_PUB_KEY_SIZE];
    octet MCPK[3]={
        {0,sizeof(m1),m1},{0,sizeof(m2),m2},{0,sizeof(m3),m3}
    };

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
   
    char tick[TLS_MAX_TICKET_SIZE];    // A resumption ticket
    octet TICK={0,sizeof(tick),tick};

    struct timeval time_ticket_received,time_ticket_used;

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
    bool have_early_data=true;       // Hope to send client message as early data

// Extract Ticket parameters
    lifetime=T.lifetime;
    age_obfuscator=T.age_obfuscator;
    max_early_data=T.max_early_data;
    OCT_copy(&ETICK,&T.TICK);
    OCT_copy(&NONCE,&T.NONCE);
    time_ticket_received=T.birth;

    if (lifetime<0) 
    {
        logger(fp,(char *)"Bad Ticket\n",NULL,0,NULL);
        return 0;
    }

    logTicket(fp,lifetime,age_obfuscator,max_early_data,&NONCE,&ETICK);

    if (max_early_data==0)
        have_early_data=false;      // not allowed!

// recover PSK from Resumption Master Secret and Nonce

    sha=RMS.len;   // assume this was hash used to create PSK

    RECOVER_PSK(sha,&RMS,&NONCE,&PSK);  // recover PSK from resumption master secret and ticket nonce
    logger(fp,(char *)"PSK= ",NULL,0,&PSK); 

    GET_EARLY_SECRET(sha,&PSK,&ES,NULL,&BKR);   // compute early secret and Binder Key from PSK
    logger(fp,(char *)"Binder Key= ",NULL,0,&BKR); 
    logger(fp,(char *)"Early Secret= ",NULL,0,&ES);

// allow for up to 3 tickets... 
    char t1[TLS_MAX_TICKET_SIZE],t2[TLS_MAX_TICKET_SIZE],t3[TLS_MAX_TICKET_SIZE];
    octet PSKID[3]={
        {0,sizeof(t1),t1},{0,sizeof(t2),t2},{0,sizeof(t3),t3}
    };
    OCT_copy(&PSKID[0],&ETICK);   // .. but we only use one

    char b1[TLS_MAX_HASH+1],b2[TLS_MAX_HASH+1],b3[TLS_MAX_HASH+1];
    octet BINDERS[3]={
        {0,sizeof(b1),b1},{0,sizeof(b2),b2},{0,sizeof(b3),b3}
    };    

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&CPK);

    logger(fp,(char *)"Private key= ",NULL,0,&CSK);  
    logger(fp,(char *)"Client Public key= ",NULL,0,&CPK);  

// Prepare for extensions
    tlsVersion=TLS1_3;
    pskMode=PSKWECDHE;

// Construct vector of public keys
    OCT_copy(&MCPK[0],&CPK);   // Just one Public Key Share

// Client Hello
// First build client Hello extensions
    OCT_clear(&EXT);
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
    addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
    addKeyShareExt(&EXT,1,kexGroups,MCPK);  // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);                      // ask for max fragment length of 4096
    if (have_early_data)
        addEarlyDataExt(&EXT);                                     // try sending client message as early data if allowed

    unsign32 age[3];  // up to 3 tickets
    gettimeofday(&time_ticket_used, NULL);
    age[0]= milliseconds(time_ticket_received,time_ticket_used);   // age of ticket in milliseconds - problem for some sites which work for age[0]=0; ??
    logger(fp,(char *)"Ticket age= ",(char *)"%x",age[0],NULL);
    age[0]+=age_obfuscator;
    logger(fp,(char *)"obfuscated age = ",(char *)"%x",age[0],NULL);
    int extra=addPreSharedKeyExt(&EXT,1,age,PSKID,sha); 

// create and send Client Hello Octet
    sendClientHello(client,TLS1_2,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,extra,&IO);  
    logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
    logger(fp,(char *)"Client Hello sent\n",NULL,0,NULL);

    unihash tlshash;
    Hash_Init(sha,&tlshash);
    running_hash(&CH,&tlshash);  
    transcript_hash(&tlshash,&HH); // hash of Truncated clientHello

    char bnd[TLS_MAX_HASH];
    octet BND={0,sizeof(bnd),bnd};

    VERIFY_DATA(sha,&BND,&BKR,&HH);
    logger(fp,(char *)"BND= ",NULL,0,&BND);
    OCT_copy(&BINDERS[0],&BND);

    char bl[3*TLS_MAX_HASH+3];
    octet BL={0,sizeof(bl),bl};

    logger(fp,(char *)"Sending Binders\n",NULL,0,NULL);   // only sending one
    sendBindersList(client,&BL,1,BINDERS,&IO);          // the rest of clientHello
    logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
    running_hash(&BL,&tlshash);
    transcript_hash(&tlshash,&HH);  // hash of full clientHello

    if (have_early_data)
        sendCCCS(client);

    GET_LATER_SECRETS(sha,&ES,&HH,&CETS,NULL); // Get Client Early Traffic Secret from transcript hash and ES
    logger(fp,(char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
    GET_KEY_AND_IV(cipher_suite,&CETS,&K_send);  // Set Client K_send to early data keys 

// if its allowed, send client message as (encrypted) early data
    if (have_early_data)
    {
        logger(fp,(char *)"Sending some early data\n",NULL,0,NULL);
        client_send(fp,client,hostname,&K_send,true,&IO);
    }

// Process Server Hello
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&SPK,pskid);

    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    logServerHello(fp,cipher_suite,kex,pskid,&SPK,&COOK);

    if (rtn==HANDSHAKE_RETRY)
    { // should not happen
        logger(fp,(char *)"No change possible as result of HRR\n",NULL,0,NULL); 
        sendClientAlert(client,UNEXPECTED_MESSAGE,&K_send,&IO);
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    logger(fp,(char *)"serverHello= ",NULL,0,&IO); 
 
    if (pskid<0)
    { // Ticket rejected by Server as out of date??
        logger(fp,(char *)"Preshared key rejected by server\n",NULL,0,NULL);
        return 0;
    }

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
    if (sha==0) return 0;

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    GENERATE_SHARED_SECRET(kex,&CSK,&SPK,&SS);
    logger(fp,(char *)"Key Exchange= ",(char *)"%d",kex,NULL);
    logger(fp,(char *)"Shared Secret= ",NULL,0,&SS);

    running_hash(&IO,&tlshash);
    transcript_hash(&tlshash,&HH);       // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS); 
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);
    logger(fp,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(fp,(char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger(fp,(char *)"Server handshake traffic secret= ",NULL,0,&STS);

// 1. get encrypted extensions
    OCT_clear(&IO);
    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,early_data_accepted);
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    if (early_data_accepted)
        logger(fp,(char *)"Early Data Accepted\n",NULL,0,NULL);
    else
        logger(fp,(char *)"Early Data was NOT Accepted\n",NULL,0,NULL);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension
    logger(fp,(char *)"Transcript Hash= ",NULL,0,&FH); 

// 2. get server finish
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);   // Finished
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    logger(fp,(char *)"IO.len= ",(char *)"%d",IO.len,NULL);
    
// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (early_data_accepted)
    {
        logger(fp,(char *)"Send End of Early Data \n",NULL,0,NULL);
        sendEndOfEarlyData(client,&K_send,&tlshash,&IO);                 // Should only be sent if server has accepted Early data - see encrypted extensions!
        logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
    }

    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
    logger(fp,(char *)"Transcript Hash= ",NULL,0,&TH); 

// Switch to handshake keys
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        logger(fp,(char *)"Server Data is verified\n",NULL,0,NULL);
    else
    {
        logger(fp,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        return 0;
    }
// create client verify data
// and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    logger(fp,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    sendClientVerify(client,&K_send,&tlshash,&CHF,&IO);   
    logger(fp,(char *)"Client to Server -> ",NULL,0,&IO);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&HH,NULL,&CTS,&STS,NULL,NULL);  
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

    logger(fp,(char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger(fp,(char *)"Server application traffic secret= ",NULL,0,&STS);

// Start the Application - send HTML GET command
    if (!early_data_accepted)
        client_send(fp,client,hostname,&K_send,false,&IO);

// Process server responses
    rtn=processServerMessage(fp,client,&IO,&K_recv,&STS,&TICK,&time_ticket_received); 
    logServerResponse(fp,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }

    init_ticket_context(&T,time_ticket_received); // initialise and time-stamp a new ticket
    parseTicket(&TICK,&T);  // extract into ticket structure

    if (early_data_accepted) return 2;
    return 1;
}

// Main program
// 1. Connect to Website
// 2. Decide cryptographic capabilities
// 3. Do a Full TLS1.3 handshake
// 4. Attempt resumption with Early data after time-out

int main(int argc, char const *argv[])
{
    char hostname[TLS_MAX_SERVER_NAME];
//    char ip[40];
    int  port, rtn, sha; 
    int favourite_group;
    char rms[TLS_MAX_HASH];
    octet RMS = {0,sizeof(rms),rms};   // Resumption master secret
    char raw[200];
    octet RAW = {0, sizeof(raw), raw}; // Some initial entropy

    ticket T;
    capabilities CPB;

    struct timeval time_ticket_received,time_ticket_used;

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

    FILE *fp=fopen("logger.log","wt");
    //FILE *fp=stdout;                     // for verbose output

// Make Socket connection
    argv++; argc--;

    if (argc!=1)
    {
        strcpy(hostname,"localhost");
        port=4433;
    } else {
        strcpy(hostname,argv[0]);
        logger(fp,(char *)"Hostname= ",hostname,0,NULL);
        port=443;
    }
    Socket client;
    if (!client.connect(hostname,port))
    {
        logger(fp,(char *)"Unable to access ",hostname,0,NULL);
 		return 0;
    }

// Client Capabilities to be advertised
// Supported Key Exchange Groups in order of preference
    CPB.nsg=3;
    CPB.supportedGroups[0]=X25519;
    CPB.supportedGroups[1]=SECP256R1;
    CPB.supportedGroups[2]=SECP384R1;

// Supported Cipher Suits
    CPB.nsc=2;     
    CPB.ciphers[0]=TLS_AES_128_GCM_SHA256;
    CPB.ciphers[1]=TLS_AES_256_GCM_SHA384;
  //  ciphers[2]=TLS_CHACHA20_POLY1305_SHA256;  // not supported

// Extensions
// Supported Cert signing Algorithms - could add more
    CPB.nsa=8;
    CPB.sigAlgs[0]=ECDSA_SECP256R1_SHA256;
    CPB.sigAlgs[1]=RSA_PSS_RSAE_SHA256;
    CPB.sigAlgs[2]=RSA_PKCS1_SHA256;
    CPB.sigAlgs[3]=ECDSA_SECP384R1_SHA384;
    CPB.sigAlgs[4]=RSA_PSS_RSAE_SHA384;
    CPB.sigAlgs[5]=RSA_PKCS1_SHA384;
    CPB.sigAlgs[6]=RSA_PSS_RSAE_SHA512;
    CPB.sigAlgs[7]=RSA_PKCS1_SHA512;
    CPB.sigAlgs[8]=RSA_PKCS1_SHA1;

// Do full TLS 1.3 handshake
    rtn=TLS13_full(fp,client,hostname,RNG,favourite_group,CPB,RMS,T);
    if (rtn)
    {
        myprintf((char *)"Full Handshake succeeded\n");
        if (rtn==2) myprintf((char *)"... after handshake resumption\n");
    }
    else {
        myprintf((char *)"Full Handshake failed\n");
        return 0;
    }

    //close(client);  // After time out, exit and close session
    client.close();
    logger(fp,(char *)"Connection closed\n",NULL,0,NULL);

// reopen socket - attempt resumption

    if (T.lifetime==0)
    {
        myprintf((char *)"No Ticket provided - unable to resume\n");
        return 0;
    }

    myprintf((char *)"\nAttempting resumption\n");

//    client=setclientsock(port,ip);
    if (!client.connect(hostname,port))
    {
        logger(fp,(char *)"\nConnection Failed \n",NULL,0,NULL); 
        return 0;
    }

    rtn=TLS13_resume(fp,client,hostname,RNG,favourite_group,CPB,RMS,T);
    if (rtn)
    {
        myprintf((char *)"Resumption Handshake succeeded\n");
        if (rtn==2) myprintf((char *)"Early data was accepted\n");
    } else {
        myprintf((char *)"Resumption Handshake failed\n");
        return 0;
    }

    client.close();  // After time out, exit and close session
    logger(fp,(char *)"Connection closed\n",NULL,0,NULL);

    return 0;
}

