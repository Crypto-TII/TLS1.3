// Main TLS1.3 protocol

#include "tls_protocol.h"

// TLS1.3 full handshake
// client - socket connection
// hostname - website for connection
// RNG - Random Number generator
// favourite group - may be changed on handshake retry
// Capabilities - the supported crypto primitives
// RMS - returned Resumption Master secret
// T - returned resumption ticket
// K_send - Sending Key
// K_recv - Receiving Key
// STS - Server traffic secret
int TLS13_full(Socket &client,char *hostname,csprng &RNG,int &favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS)
{
    int i,rtn,pskid;
    int cipher_suite,cs_hrr,kex,sha;
    int kexGroups[TLS_MAX_KEY_SHARES];
    bool early_data_accepted,ccs_sent=false;
    bool resumption_required=false;

    char csk[TLS_MAX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octet CSK = {0, sizeof(csk), csk};
    char pk[TLS_MAX_PUB_KEY_SIZE];       // Server & Client Public Key (shared memory)
    octet PK = {0, sizeof(pk), pk};
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};      // Shared Secret and Server's Cert Public Key (shared memory)
    char ch[TLS_MAX_CLIENT_HELLO];       // Client Hello
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
    octet CTS = {0,sizeof(cts),cts};     // client traffic secret
    char cid[32];                       
    octet CID={0,sizeof(cid),cid};       // Client session ID
    char cook[TLS_MAX_COOKIE];
    octet COOK={0,sizeof(cook),cook};    // Cookie
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octet SCVSIG={0,sizeof(scvsig),scvsig};           // Server's digital signature on transcript
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octet CHF={0,sizeof(chf),chf};                    // client verify

    char cets[TLS_MAX_HASH];           
    octet CETS={0,sizeof(cets),cets};   // Early traffic secret

    struct timeval time_ticket_received;

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    favourite_group=CPB.supportedGroups[0]; // only sending one key share in favourite group
//
// Generate key pair in favourite group
//
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&PK);

    logger(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);
    logger(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&PK);

// Choose public key group
    kexGroups[0]=favourite_group;

// Client Hello
// First build our preferred mix of client Hello extensions, based on our capabililities
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
    addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
    addKeyShareExt(&EXT,favourite_group,&PK); // only sending one public key
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);   // ask for smaller max fragment length of 4096 - server may not agree - but no harm in asking

// create and send Client Hello Octet
    sendClientHello(client,TLS1_0,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,0,&IO);   
    logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO); 
    logger(IO_DEBUG,(char *)"Client Hello sent\n",NULL,0,NULL);

// Process Server Hello response
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&PK,pskid);
    logServerResponse(IO_DEBUG,rtn,&IO);
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
        logger(IO_DEBUG,(char *)"Cipher_suite not valid ",(char *)"%x",cipher_suite,NULL);
        sendClientAlert(client,UNEXPECTED_MESSAGE,NULL,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);     
        return 0;
    }
    logger(IO_DEBUG,(char *)"Cipher suite= ",(char *)"%x",cipher_suite,NULL);

    GET_EARLY_SECRET(sha,NULL,&ES,NULL,NULL);   // Early Secret

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function which could be SHA256 or SHA384
    unihash tlshash;
    Hash_Init(sha,&tlshash);    

// Did serverHello ask for HelloRetryRequest?
    if (rtn==HANDSHAKE_RETRY)
    {
        if (kex==favourite_group)
        { // its the same one I chose !?
            logger(IO_DEBUG,(char *)"No change as result of HRR\n",NULL,0,NULL); 
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL,&IO);
            logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);     
            return 0;
        }
        logger(IO_DEBUG,(char *)"Server HelloRetryRequest= ",NULL,0,&IO);
        running_syn_hash(&CH,&EXT,&tlshash); // RFC 8446 section 4.4.1
        running_hash(&IO,&tlshash);     // Hash of HelloRetryRequest

// Fix clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_clear(&EXT);
        addServerNameExt(&EXT,hostname);
        addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
        addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
// generate new key pair in new server selected group 
        favourite_group=kex;
        GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&PK); 
        kexGroups[0]=favourite_group; 
        addKeyShareExt(&EXT,favourite_group,&PK);  // Public Key Share in new group
        addPSKExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        addMFLExt(&EXT,4);                      // ask for max fragment length of 4096
        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR
        sendCCCS(client);  // send Client Cipher Change
        ccs_sent=true;

// create and send new Client Hello Octet
        sendClientHello(client,TLS1_2,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,0,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        rtn=getServerHello(client,&IO,cs_hrr,kex,&CID,&COOK,&PK,pskid);
        if (rtn==HANDSHAKE_RETRY)
        { // only one retry allowed
            logger(IO_DEBUG,(char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
            sendClientAlert(client,UNEXPECTED_MESSAGE,NULL,&IO);
            logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
            return 0;
        }
        if (cs_hrr!=cipher_suite)
        { // Server cannot change cipher_suite at this stage
            logger(IO_DEBUG,(char *)"Server selected different cipher suite\n",NULL,0,NULL); 
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL,&IO); 
            logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
            return 0;
        }
        resumption_required=true;
    }

    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {  
        sendClientAlert(client,alert_from_cause(rtn),NULL,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    logger(IO_DEBUG,(char *)"Server Hello= ",NULL,0,&IO); 
    logServerHello(IO_DEBUG,cipher_suite,kex,pskid,&PK,&COOK);

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    GENERATE_SHARED_SECRET(kex,&CSK,&PK,&SS);
    logger(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);

// Hash Transcript Hellos 
    running_hash(&CH,&tlshash);
    running_hash(&EXT,&tlshash);
    running_hash(&IO,&tlshash);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
    transcript_hash(&tlshash,&HH);              // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

    logger(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&STS);

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).

// 1. get encrypted extensions
    OCT_clear(&IO);
    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,early_data_accepted);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;
    logger(IO_DEBUG,(char *)"Encrypted Extensions Processed\n ",NULL,0,NULL);

// 2. get certificate chain, check it, get Server public key
    rtn=getCheckServerCertificateChain(client,&IO,&K_recv,&tlshash,&SS);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;
    logger(IO_DEBUG,(char *)"Certificate Chain is valid\n",NULL,0,NULL);

    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain
    logger(IO_DEBUG,(char *)"Transcript Hash= ",NULL,0,&HH); 

// 3. get verifier signature
    int sigalg;
    rtn=getServerCertVerify(client,&IO,&K_recv,&tlshash,&SCVSIG,sigalg);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
    logger(IO_DEBUG,(char *)"Transcript Hash= ",NULL,0,&FH);
    logger(IO_DEBUG,(char *)"Signature Algorithm= ",(char *)"%04x",sigalg,NULL);
    logger(IO_DEBUG,(char *)"Server Certificate Signature= ",NULL,0,&SCVSIG);

    if (IS_SERVER_CERT_VERIFY(sigalg,&SCVSIG,&HH,&SS))
        logger(IO_DEBUG,(char *)"Server Cert Verification OK\n",NULL,0,NULL);
    else
    {
        logger(IO_DEBUG,(char *)"Server Cert Verification failed\n",NULL,0,NULL);
        sendClientAlert(client,DECRYPT_ERROR,&K_send,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }

// 4. get Server Finished
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_recv,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

    logger(IO_DEBUG,(char *)"Transcript Hash= ",NULL,0,&TH);

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        logger(IO_DEBUG,(char *)"Server Data is verified\n",NULL,0,NULL);
    else
    {
        logger(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        sendClientAlert(client,DECRYPT_ERROR,&K_send,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }

    if (!ccs_sent)
        sendCCCS(client);  // send Client Cipher Change (if not already sent)

// create client verify data
// .... and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    logger(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    sendClientVerify(client,&K_send,&tlshash,&CHF,&IO);   
    logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&TH,&FH,&CTS,&STS,NULL,&RMS);
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);
    logger(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&STS);

    if (resumption_required) return 2;
    return 1;
}

// TLS1.3 resumption handshake
// client - socket connection
// hostname - website for reconnection
// RNG - Random Number generator
// favourite group - as selected on previous connection
// Capabilities - the supported crypto primitives
// RMS - Resumption Master secret from previous session
// T - Resumption ticket
// K_send - Sending Key
// K_recv - Receiving Key
// STS - Server traffic secret
// EARLY - First message from Client to Server (should ideally be sent as early data!)
int TLS13_resume(Socket &client,char *hostname,csprng &RNG,int favourite_group,capabilities &CPB,octet &IO,octet &RMS,ticket &T,crypto &K_send,crypto &K_recv,octet &STS,octet &EARLY)
{
    int sha,rtn,kex,cipher_suite,pskid;
    int kexGroups[TLS_MAX_KEY_SHARES];
    bool early_data_accepted;
    kexGroups[0]=favourite_group;

    char es[TLS_MAX_HASH];               // Early Secret
    octet ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octet HS = {0,sizeof(hs),hs};
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octet SS = {0, sizeof(ss), ss};      // Shared Secret
    char csk[TLS_MAX_SECRET_KEY_SIZE];   
    octet CSK = {0, sizeof(csk), csk};   // clients key exchange secret key
    char pk[TLS_MAX_PUB_KEY_SIZE];
    octet PK = {0, sizeof(pk), pk};   // Servers key exchange Public Key
    char ch[TLS_MAX_CLIENT_HELLO];    // Client Hello
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
    octet CTS = {0,sizeof(cts),cts};    // client traffic secret
    char fin[TLS_MAX_HASH];
    octet FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octet CHF={0,sizeof(chf),chf};                    // client verify
    char cets[TLS_MAX_HASH];           
    octet CETS={0,sizeof(cets),cets};   // Early traffic secret
    char cid[32];                       
    octet CID={0,sizeof(cid),cid};      // Client session ID
    char cook[TLS_MAX_COOKIE];
    octet COOK={0,sizeof(cook),cook};   // Cookie
    char bnd[TLS_MAX_HASH];
    octet BND={0,sizeof(bnd),bnd};
    char bl[TLS_MAX_HASH+3];
    octet BL={0,sizeof(bl),bl};
    char psk[TLS_MAX_HASH];
    octet PSK={0,sizeof(psk),psk};     // Pre-shared key
    char bkr[TLS_MAX_HASH];
    octet BKR={0,sizeof(bkr),bkr};     // Binder secret
    char nonce[32];
    octet NONCE={0,sizeof(nonce),nonce}; // ticket nonce
    char etick[TLS_MAX_TICKET_SIZE];
    octet ETICK={0,sizeof(etick),etick}; // ticket

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    struct timeval time_ticket_received,time_ticket_used;
    int lifetime=0;
    unsign32 age,age_obfuscator=0;
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
        logger(IO_DEBUG,(char *)"Bad Ticket\n",NULL,0,NULL);
        return 0;
    }
    logTicket(IO_DEBUG,lifetime,age_obfuscator,max_early_data,&NONCE,&ETICK);
    if (max_early_data==0)
        have_early_data=false;      // early data not allowed!

// recover PSK from Resumption Master Secret and Nonce

    sha=RMS.len;   // assume this was hash used to create PSK

    RECOVER_PSK(sha,&RMS,&NONCE,&PSK);  // recover PSK from resumption master secret and ticket nonce
    logger(IO_DEBUG,(char *)"PSK= ",NULL,0,&PSK); 

    GET_EARLY_SECRET(sha,&PSK,&ES,NULL,&BKR);   // compute early secret and Binder Key from PSK
    logger(IO_DEBUG,(char *)"Binder Key= ",NULL,0,&BKR); 
    logger(IO_DEBUG,(char *)"Early Secret= ",NULL,0,&ES);

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
    GENERATE_KEY_PAIR(&RNG,favourite_group,&CSK,&PK);

    logger(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);  
    logger(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&PK);  

// Client Hello
// First build client Hello extensions
    OCT_clear(&EXT);
    addServerNameExt(&EXT,hostname);
    addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
    addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
    addKeyShareExt(&EXT,favourite_group,&PK); // only sending one public key 
    addPSKExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);                        // ask for max fragment length of 4096
    if (have_early_data)
        addEarlyDataExt(&EXT);                // try sending client message as early data if allowed

    gettimeofday(&time_ticket_used, NULL);
    age= milliseconds(time_ticket_received,time_ticket_used);    // age of ticket in milliseconds - problem for some sites which work for age=0 ??
    logger(IO_DEBUG,(char *)"Ticket age= ",(char *)"%x",age,NULL);
    age+=age_obfuscator;
    logger(IO_DEBUG,(char *)"obfuscated age = ",(char *)"%x",age,NULL);
    int extra=addPreSharedKeyExt(&EXT,age,&ETICK,sha);
// create and send Client Hello Octet
    sendClientHello(client,TLS1_2,&CH,CPB.nsc,CPB.ciphers,&RNG,&CID,&EXT,extra,&IO);  
    logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
    logger(IO_DEBUG,(char *)"Client Hello sent\n",NULL,0,NULL);

    unihash tlshash;
    Hash_Init(sha,&tlshash);
    running_hash(&CH,&tlshash); 
    running_hash(&EXT,&tlshash);
    transcript_hash(&tlshash,&HH);            // hash of Truncated clientHello

    VERIFY_DATA(sha,&BND,&BKR,&HH);
    logger(IO_DEBUG,(char *)"BND= ",NULL,0,&BND);

    logger(IO_DEBUG,(char *)"Sending Binders\n",NULL,0,NULL);   // only sending one
    sendBinder(client,&BL,&BND,&IO);
    logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
    running_hash(&BL,&tlshash);
    transcript_hash(&tlshash,&HH);            // hash of full clientHello

    if (have_early_data)
        sendCCCS(client);

    GET_LATER_SECRETS(sha,&ES,&HH,&CETS,NULL);   // Get Client Early Traffic Secret from transcript hash and ES
    logger(IO_DEBUG,(char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
    GET_KEY_AND_IV(cipher_suite,&CETS,&K_send);  // Set Client K_send to early data keys 

// if its allowed, send client message as (encrypted) early data
    if (have_early_data)
    {
        logger(IO_DEBUG,(char *)"Sending some early data\n",NULL,0,NULL);
        //client_send(client,&EARLY,&K_send,&IO);
        logger(IO_APPLICATION,(char *)"Sending Application Message\n\n",EARLY.val,0,NULL);
        sendClientMessage(client,APPLICATION,TLS1_2,&K_send,&EARLY,NULL,&IO);
    }

// Process Server Hello
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&PK,pskid);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    logServerHello(IO_DEBUG,cipher_suite,kex,pskid,&PK,&COOK);

    if (rtn==HANDSHAKE_RETRY)
    { // should not happen
        logger(IO_DEBUG,(char *)"No change possible as result of HRR\n",NULL,0,NULL); 
        sendClientAlert(client,UNEXPECTED_MESSAGE,&K_send,&IO);
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
        return 0;
    }
    logger(IO_DEBUG,(char *)"serverHello= ",NULL,0,&IO); 
 
    if (pskid<0)
    { // Ticket rejected by Server (as out of date??)
        logger(IO_DEBUG,(char *)"Preshared key rejected by server\n",NULL,0,NULL);
        return 0;
    }

// Check which cipher-suite chosen by Server
    sha=0;
    if (cipher_suite==TLS_AES_128_GCM_SHA256) sha=32;
    if (cipher_suite==TLS_AES_256_GCM_SHA384) sha=48;
    if (sha==0) return 0;

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    GENERATE_SHARED_SECRET(kex,&CSK,&PK,&SS);
    logger(IO_DEBUG,(char *)"Key Exchange= ",(char *)"%d",kex,NULL);
    logger(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);

    running_hash(&IO,&tlshash);
    transcript_hash(&tlshash,&HH);       // hash of clientHello+serverHello
    GET_HANDSHAKE_SECRETS(sha,&SS,&ES,&HH,&HS,&CTS,&STS); 
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);
    logger(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&STS);

// 1. get encrypted extensions
    OCT_clear(&IO);
    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,early_data_accepted);
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;

    if (early_data_accepted)
        logger(IO_DEBUG,(char *)"Early Data Accepted\n",NULL,0,NULL);
    else
        logger(IO_DEBUG,(char *)"Early Data was NOT Accepted\n",NULL,0,NULL);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension
    logger(IO_DEBUG,(char *)"Transcript Hash= ",NULL,0,&FH); 

// 2. get server finish
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);   // Finished
    logServerResponse(IO_DEBUG,rtn,&IO);
    if (rtn<0)
    {
        sendClientAlert(client,alert_from_cause(rtn),&K_send,&IO);
        return 0;
    }
    if (rtn==TIME_OUT || rtn==ALERT)
        return 0;
    logger(IO_DEBUG,(char *)"IO.len= ",(char *)"%d",IO.len,NULL);
    
// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcript_hash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (early_data_accepted)
    {
        logger(IO_DEBUG,(char *)"Send End of Early Data \n",NULL,0,NULL);
        sendEndOfEarlyData(client,&K_send,&tlshash,&IO);     // Should only be sent if server has accepted Early data - see encrypted extensions!
        logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
    }
    transcript_hash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
    logger(IO_DEBUG,(char *)"Transcript Hash= ",NULL,0,&TH); 

// Switch to handshake keys
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);

    if (IS_VERIFY_DATA(sha,&FIN,&STS,&FH))
        logger(IO_DEBUG,(char *)"Server Data is verified\n",NULL,0,NULL);
    else
    {
        logger(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        return 0;
    }
// create client verify data and send it to Server
    VERIFY_DATA(sha,&CHF,&CTS,&TH);  
    logger(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    sendClientVerify(client,&K_send,&tlshash,&CHF,&IO);   
    logger(IO_DEBUG,(char *)"Client to Server -> ",NULL,0,&IO);
    transcript_hash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    GET_APPLICATION_SECRETS(sha,&HS,&HH,NULL,&CTS,&STS,NULL,NULL);  
    GET_KEY_AND_IV(cipher_suite,&CTS,&K_send);
    GET_KEY_AND_IV(cipher_suite,&STS,&K_recv);

    logger(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&STS);

    if (early_data_accepted) return 2;
    return 1;
}
