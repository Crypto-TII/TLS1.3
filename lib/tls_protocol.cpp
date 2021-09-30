//
// Main TLS1.3 protocol
//

#include "tls_protocol.h"

static const char *http= (const char *)"687474702f312e31"; // http/1.1

// TLS1.3 full handshake
// client - socket connection
// hostname - website for connection
// IO - main input/output buffer
// RMS - returned Resumption Master secret
// K_send - Sending Key
// K_recv - Receiving Key
// STS - Server traffic secret
// Capabilities - the supported crypto primitives
// cipher_suite - agreed cipher suite 
// favourite key exchange group - may be changed on handshake retry
int TLS13_full(Socket &client,char *hostname,octad &IO,octad &RMS,crypto &K_send,crypto &K_recv,octad &STS,capabilities &CPB,int &cipher_suite,int &favourite_group)
{
    ret rtn;
    int i,pskid;
    int cs_hrr,kex,hashtype,hashlen;
    bool ccs_sent=false;
    bool resumption_required=false;
    bool gotacertrequest=false;
    int nccsalgs=0;  // number of client certificate signature algorithms
    int csigAlgs[TLS_MAX_SUPPORTED_SIGS]; // acceptable client cert signature types

    char csk[TLS_MAX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octad CSK = {0, sizeof(csk), csk};
    char pk[TLS_MAX_PUB_KEY_SIZE];       // Server & Client Public Key (shared memory)
    octad PK = {0, sizeof(pk), pk};
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octad SS = {0, sizeof(ss), ss};      // Shared Secret and Server's Cert Public Key (shared memory)
    char ch[TLS_MAX_CLIENT_HELLO];       // Client Hello
    octad CH = {0, sizeof(ch), ch};
    char ext[TLS_MAX_EXTENSIONS];
    octad EXT={0,sizeof(ext),ext};       // Extensions                  
    char es[TLS_MAX_HASH];               // Early Secret
    octad ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octad HS = {0,sizeof(hs),hs};
    char hh[TLS_MAX_HASH];               
    octad HH={0,sizeof(hh),hh};          // Transcript hashes
    char fh[TLS_MAX_HASH];
    octad FH={0,sizeof(fh),fh};       
    char th[TLS_MAX_HASH];
    octad TH={0,sizeof(th),th};  
    char cts[TLS_MAX_HASH];
    octad CTS = {0,sizeof(cts),cts};     // client traffic secret
    char cid[32];                       
    octad CID={0,sizeof(cid),cid};       // Client session ID
    char cook[TLS_MAX_COOKIE];
    octad COOK={0,sizeof(cook),cook};    // Cookie
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octad SCVSIG={0,sizeof(scvsig),scvsig};           // Server's digital signature on transcript
    char fin[TLS_MAX_HASH];
    octad FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octad CHF={0,sizeof(chf),chf};                    // client verify
    char cets[TLS_MAX_HASH];           
    octad CETS={0,sizeof(cets),cets};   // Early traffic secret
    char alpn[8];
    octad ALPN={0,sizeof(alpn),alpn};         // ALPN

#ifdef HAVE_A_CLIENT_CERT
    char client_key[TLS_MAX_MYCERT_SIZE];           
    octad CLIENT_KEY={0,sizeof(client_key),client_key};   // Early traffic secret
    char client_cert[TLS_MAX_MYCERT_SIZE];           
    octad CLIENT_CERTCHAIN={0,sizeof(client_cert),client_cert};   // Early traffic secret
    char ccvsig[TLS_MAX_SIGNATURE_SIZE];
    octad CCVSIG={0,sizeof(ccvsig),ccvsig};           // Client's digital signature on transcript
#endif

#ifdef TLS_PROTOCOL
#if TLS_PROTOCOL == TLS_HTTP_PROTOCOL
    OCT_from_hex(&ALPN,(char *)http);
#endif
#endif

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    ee_resp enc_ext_resp={false,false,false,false};  // encrypted extensions expectations
    ee_expt enc_ext_expt={false,false,false,false};  // encrypted extensions responses
    
    favourite_group=CPB.supportedGroups[0]; // only sending one key share in our favourite group
//
// Generate key pair in favourite group
//
    SAL_generateKeyPair(favourite_group,&CSK,&PK);

#if VERBOSITY >= IO_DEBUG    
    logger((char *)"Private key= ",NULL,0,&CSK);
    logger((char *)"Client Public key= ",NULL,0,&PK);
#endif

// Client Hello
// First build our preferred mix of client Hello extensions, based on our capabililities
    addServerNameExt(&EXT,hostname); enc_ext_expt.server_name=true;  // Server Name extension - acknowledgement is expected
    addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
    addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
    addSigAlgsCertExt(&EXT,CPB.nsac,CPB.sigAlgsCert);
    addKeyShareExt(&EXT,favourite_group,&PK); // only sending one public key
#ifdef TLS_PROTOCOL
    addALPNExt(&EXT,&ALPN); enc_ext_expt.alpn=true; // only supporting one application protocol
#endif
    addPSKModesExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);  enc_ext_expt.max_frag_length=true; // ask for smaller max fragment length of 4096 - server may not agree - but no harm in asking
    addPadding(&EXT,SAL_randomByte()%16);  // add some random padding (because I can)

// create and send Client Hello octad
    sendClientHello(client,TLS1_0,&CH,CPB.nsc,CPB.ciphers,&CID,&EXT,0,&IO,false);  
#if VERBOSITY >= IO_DEBUG     
    logger((char *)"Client Hello sent\n",NULL,0,NULL);
#endif

// Process Server Hello response
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&PK,pskid);
    if (badResponse(client,NULL,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
// Find cipher-suite chosen by Server
    hashtype=0;
    for (i=0;i<CPB.nsc;i++)
    {
        if (cipher_suite==CPB.ciphers[i])
            hashtype=SAL_hashType(cipher_suite);
    }
    hashlen=SAL_hashLen(hashtype);
    if (hashlen==0)
    {
        sendClientAlert(client,UNEXPECTED_MESSAGE,NULL);
        logCipherSuite(cipher_suite);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Cipher_suite not valid\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    logCipherSuite(cipher_suite);

    deriveEarlySecrets(hashtype,NULL,&ES,NULL,NULL);   // Early Secret

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Early Secret= ",NULL,0,&ES);
#endif

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
    unihash tlshash;    // Universal Hash
    SAL_hashInit(hashtype,&tlshash);    

    if (rtn.val==HANDSHAKE_RETRY)  // Did serverHello ask for HelloRetryRequest?
    {
        if (kex==favourite_group)
        { // its the same one I chose !?
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL);
#if VERBOSITY >= IO_DEBUG
            logger((char *)"No change as result of HRR\n",NULL,0,NULL);   
#endif
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server HelloRetryRequest= ",NULL,0,&IO);
#endif
        runningSyntheticHash(&CH,&EXT,&tlshash); // RFC 8446 section 4.4.1
        runningHash(&IO,&tlshash);     // Hash of HelloRetryRequest

// Fix clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_kill(&EXT);
        addServerNameExt(&EXT,hostname); 
        addSupportedGroupsExt(&EXT,CPB.nsg,CPB.supportedGroups);
        addSigAlgsExt(&EXT,CPB.nsa,CPB.sigAlgs);
        addSigAlgsCertExt(&EXT,CPB.nsac,CPB.sigAlgsCert);
// generate new key pair in new server selected group 
        favourite_group=kex;
        SAL_generateKeyPair(favourite_group,&CSK,&PK); 
        addKeyShareExt(&EXT,favourite_group,&PK);  // Public Key Share in new group
#ifdef TLS_PROTOCOL
        addALPNExt(&EXT,&ALPN); // only supporting one application protocol
#endif
        addPSKModesExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        addMFLExt(&EXT,4);                      // ask for max fragment length of 4096
        addPadding(&EXT,SAL_randomByte()%16);  // add some random padding
        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR
        sendCCCS(client);  // send Client Cipher Change
        ccs_sent=true;

// create and send new Client Hello octad
        sendClientHello(client,TLS1_2,&CH,CPB.nsc,CPB.ciphers,&CID,&EXT,0,&IO,true);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Client Hello re-sent\n",NULL,0,NULL);
#endif
        rtn=getServerHello(client,&IO,cs_hrr,kex,&CID,&COOK,&PK,pskid);
        if (badResponse(client,NULL,rtn)) 
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }
        if (rtn.val==HANDSHAKE_RETRY)
        { // only one retry allowed
#if VERBOSITY >= IO_DEBUG
            logger((char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
#endif
            sendClientAlert(client,UNEXPECTED_MESSAGE,NULL);
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }
        if (cs_hrr!=cipher_suite)
        { // Server cannot change cipher_suite at this stage
#if VERBOSITY >= IO_DEBUG
            logger((char *)"Server selected different cipher suite\n",NULL,0,NULL); 
#endif
            sendClientAlert(client,ILLEGAL_PARAMETER,NULL); 
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }
        resumption_required=true;
    }

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Hello= ",NULL,0,&IO); 
#endif
    logServerHello(cipher_suite,kex,pskid,&PK,&COOK);

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Shared Secret= ",NULL,0,&SS);
#endif
// Hash Transcript the Hellos 
    runningHash(&CH,&tlshash);
    runningHash(&EXT,&tlshash);
    runningHash(&IO,&tlshash);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret
    transcriptHash(&tlshash,&HH);              // hash of clientHello+serverHello
    deriveHandshakeSecrets(hashtype,&SS,&ES,&HH,&HS,&CTS,&STS);
    createCryptoContext(cipher_suite,&CTS,&K_send);
    createCryptoContext(cipher_suite,&STS,&K_recv);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Handshake Secret= ",NULL,0,&HS);
    logger((char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger((char *)"Client handshake key= ",NULL,0,&(K_send.K));
    logger((char *)"Client handshake iv= ",NULL,0,&(K_send.IV));
    logger((char *)"Server handshake traffic secret= ",NULL,0,&STS);
    logger((char *)"Server handshake key= ",NULL,0,&(K_recv.K));
    logger((char *)"Server handshake iv= ",NULL,0,&(K_recv.IV));
#endif
// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).

// 1. get encrypted extensions
    OCT_kill(&IO);

    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,&enc_ext_expt,&enc_ext_resp);   
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Encrypted Extensions Processed\n",NULL,0,NULL);
#endif
// 2. get certificate request (maybe..) and certificate chain, check it, get Server public key
    rtn=getWhatsNext(client,&IO,&K_recv,&tlshash);  // get message type
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

    if (rtn.val==CERT_REQUEST)
    { // 2a. optional certificate request received
        gotacertrequest=true;
        rtn=getCertificateRequest(client,&IO,&K_recv,&tlshash,nccsalgs,csigAlgs);
        if (badResponse(client,&K_send,rtn))
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }

#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Certificate Request received\n",NULL,0,NULL);
#endif
        rtn=getWhatsNext(client,&IO,&K_recv,&tlshash);  // get message type
        if (badResponse(client,&K_send,rtn)) 
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            return 0;
        }
    }

    if (rtn.val!=CERTIFICATE)
    {
        sendClientAlert(client,alert_from_cause(WRONG_MESSAGE),&K_send);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    rtn=getCheckServerCertificateChain(client,&IO,&K_recv,&tlshash,hostname,&SS);
    if (badResponse(client,&K_send,rtn))     
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    transcriptHash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Certificate Chain is valid\n",NULL,0,NULL);
    logger((char *)"Transcript Hash (CH+SH+EE+CT) = ",NULL,0,&HH); 
#endif
// 3. get verifier signature
    int sigalg;

    rtn=getWhatsNext(client,&IO,&K_recv,&tlshash);  // get message type
    if (badResponse(client,&K_send,rtn))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    if (rtn.val!=CERT_VERIFY)
    {
        sendClientAlert(client,alert_from_cause(WRONG_MESSAGE),&K_send);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    rtn=getServerCertVerify(client,&IO,&K_recv,&tlshash,&SCVSIG,sigalg);
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

    transcriptHash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV) = ",NULL,0,&FH);
    logger((char *)"Server Certificate Signature= ",NULL,0,&SCVSIG);
#endif
    logSigAlg(sigalg);
    if (!checkServerCertVerifier(sigalg,&SCVSIG,&HH,&SS))
    {
        sendClientAlert(client,DECRYPT_ERROR,&K_send);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Cert Verification failed\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Cert Verification OK\n",NULL,0,NULL);
#endif
// 4. get Server Finished
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);
    if (badResponse(client,&K_send,rtn))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

    if (!checkVeriferData(hashtype,&FIN,&STS,&FH))
    {
        sendClientAlert(client,DECRYPT_ERROR,&K_send);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Data is NOT verified\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"\nServer Data is verified\n",NULL,0,NULL);
#endif
    if (!ccs_sent)
        sendCCCS(client);  // send Client Cipher Change (if not already sent)
    transcriptHash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

// Now its the clients turn to respond
// Send Certificate (if it was asked for, and if I have one) & Certificate Verify.
    if (gotacertrequest)
    {
#ifdef HAVE_A_CLIENT_CERT
        int kind=getClientPrivateKeyandCertChain(nccsalgs,csigAlgs,&CLIENT_KEY,&CLIENT_CERTCHAIN);
        if (kind!=0)
        { // Yes, I can do that kind of signature
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Client is authenticating\n",NULL,0,NULL);
#endif
            sendClientCertificateChain(client,&K_send,&tlshash,&CLIENT_CERTCHAIN,&IO);
            transcriptHash(&tlshash,&TH);
            createClientCertVerifier(kind,&TH,&CLIENT_KEY,&CCVSIG);      
            sendClientCertVerify(client,&K_send,&tlshash,kind,&CCVSIG,&IO);
        } else { // No, I can't - send a null cert
            sendClientCertificateChain(client,&K_send,&tlshash,NULL,&IO);
        }
#else
        sendClientCertificateChain(client,&K_send,&tlshash,NULL,&IO);
#endif
        transcriptHash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish+clientCertChain+clientCertVerify
    } else {
        OCT_copy(&TH,&HH);
    }

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = ",NULL,0,&TH);
#endif

// create client verify data
// .... and send it to Server
    deriveVeriferData(hashtype,&CHF,&CTS,&TH);  
    sendClientFinish(client,&K_send,&tlshash,&CHF,&IO);  
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Verify Data= ",NULL,0,&CHF); 
#endif
    transcriptHash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish(+clientCertChain+clientCertVerify)+clientFinish

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",NULL,0,&FH);
#endif

// calculate traffic and application keys from handshake secret and transcript hashes
    deriveApplicationSecrets(hashtype,&HS,&HH,&FH,&CTS,&STS,NULL,&RMS);

    createCryptoContext(cipher_suite,&CTS,&K_send);
    createCryptoContext(cipher_suite,&STS,&K_recv);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger((char *)"Server application traffic secret= ",NULL,0,&STS);
#endif
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Full Handshake concluded\n",NULL,0,NULL);
    if (resumption_required) logger((char *)"... after handshake resumption\n",NULL,0,NULL);
#endif
    if (resumption_required) return 2;
    return 1;
}

// TLS1.3 resumption handshake
// client - socket connection
// hostname - website for reconnection
// IO - main input/output buffer
// RMS - returned Resumption Master secret
// K_send - Sending Key
// K_recv - Receiving Key
// STS - Server traffic secret
// T - Resumption ticket
// EARLY - First message from Client to Server (should ideally be sent as early data!)
int TLS13_resume(Socket &client,char *hostname,octad &IO,octad &RMS,crypto &K_send,crypto &K_recv,octad &STS,ticket &T,octad &EARLY)
{
    int hashtype,hashlen,kex,cipher_suite,pskid,favourite_group;
    ret rtn;
    char es[TLS_MAX_HASH];               // Early Secret
    octad ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octad HS = {0,sizeof(hs),hs};
    char ss[TLS_MAX_PUB_KEY_SIZE];
    octad SS = {0, sizeof(ss), ss};      // Shared Secret
    char csk[TLS_MAX_SECRET_KEY_SIZE];   
    octad CSK = {0, sizeof(csk), csk};   // clients key exchange secret key
    char pk[TLS_MAX_PUB_KEY_SIZE];
    octad PK = {0, sizeof(pk), pk};   // Servers key exchange Public Key
    char ch[TLS_MAX_CLIENT_HELLO];    // Client Hello
    octad CH = {0, sizeof(ch), ch};
    char ext[TLS_MAX_EXTENSIONS];
    octad EXT={0,sizeof(ext),ext};       // Extensions  
    char hh[TLS_MAX_HASH];               
    octad HH={0,sizeof(hh),hh};          // Transcript hashes
    char fh[TLS_MAX_HASH];
    octad FH={0,sizeof(fh),fh};       
    char th[TLS_MAX_HASH];
    octad TH={0,sizeof(th),th};  
    char cts[TLS_MAX_HASH];
    octad CTS = {0,sizeof(cts),cts};    // client traffic secret
    char fin[TLS_MAX_HASH];
    octad FIN={0,sizeof(fin),fin};                    // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octad CHF={0,sizeof(chf),chf};                    // client verify
    char cets[TLS_MAX_HASH];           
    octad CETS={0,sizeof(cets),cets};   // Early traffic secret
    char cid[32];                       
    octad CID={0,sizeof(cid),cid};      // Client session ID
    char cook[TLS_MAX_COOKIE];
    octad COOK={0,sizeof(cook),cook};   // Cookie
    char bnd[TLS_MAX_HASH];
    octad BND={0,sizeof(bnd),bnd};
    char bl[TLS_MAX_HASH+3];
    octad BL={0,sizeof(bl),bl};
    char psk[TLS_MAX_HASH];
    octad PSK={0,sizeof(psk),psk};     // Pre-shared key
    char bk[TLS_MAX_HASH];
    octad BK={0,sizeof(bk),bk};     // Binder key
    char nonce[32];
    octad NONCE={0,sizeof(nonce),nonce}; // ticket nonce
    char etick[TLS_MAX_TICKET_SIZE];
    octad ETICK={0,sizeof(etick),etick}; // ticket
    char alpn[8];
    octad ALPN={0,sizeof(alpn),alpn};         // ALPN

#ifdef TLS_PROTOCOL
#if TLS_PROTOCOL == TLS_HTTP_PROTOCOL
    OCT_from_hex(&ALPN,(char *)http);
#endif
#endif

// NOTE: MAX_TICKET_SIZE and MAX_EXTENSIONS are increased to support much larger tickets issued when client certificate authentication required

    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
    unsign32 time_ticket_received,time_ticket_used;
    int origin,lifetime=0;
    unsign32 age,age_obfuscator=0;
    unsign32 max_early_data=0;
    bool have_early_data=true;       // Hope to send client message as early data
    bool external_psk=false;
    ee_resp enc_ext_resp={false,false,false,false};  // encrypted extensions expectations
    ee_expt enc_ext_expt={false,false,false,false};  // encrypted extensions responses

// Extract Ticket parameters
    lifetime=T.lifetime;
    age_obfuscator=T.age_obfuscator;
    max_early_data=T.max_early_data;
    OCT_copy(&ETICK,&T.TICK);
    OCT_copy(&NONCE,&T.NONCE);
    OCT_copy(&PSK,&T.PSK);
    time_ticket_received=T.birth;
    cipher_suite=T.cipher_suite;
    favourite_group=T.favourite_group;
    origin=T.origin;

    if (lifetime<0) 
    {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Bad Ticket\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    logTicket(&T); // lifetime,age_obfuscator,max_early_data,&NONCE,&ETICK);

    if (max_early_data==0)
        have_early_data=false;      // early data not allowed!

// Generate Early secret and Binder Key from PSK

    hashtype=SAL_hashType(cipher_suite);
    hashlen=SAL_hashLen(hashtype); // get hash function output length

    if (time_ticket_received==0 && age_obfuscator==0)
    { // its an external PSK
        external_psk=true;
        deriveEarlySecrets(hashtype,&PSK,&ES,&BK,NULL);
    } else {
        external_psk=false;
        deriveEarlySecrets(hashtype,&PSK,&ES,NULL,&BK);   // compute early secret and Binder Key from PSK
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"PSK= ",NULL,0,&PSK); 
    logger((char *)"Binder Key= ",NULL,0,&BK); 
    logger((char *)"Early Secret= ",NULL,0,&ES);
#endif
// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
    SAL_generateKeyPair(favourite_group,&CSK,&PK);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Private key= ",NULL,0,&CSK);  
    logger((char *)"Client Public key= ",NULL,0,&PK);  
#endif

// Client Hello
// First build client Hello extensions
    OCT_kill(&EXT);

    addServerNameExt(&EXT,hostname); enc_ext_expt.server_name=true;
    int groups[1]; groups[0]=favourite_group;    // Only allow one group
    addSupportedGroupsExt(&EXT,1,groups);                
// Signature algorithms not needed for resumption, so smaller clientHello
    addKeyShareExt(&EXT,favourite_group,&PK); // only sending one public key 
#ifdef TLS_PROTOCOL
    addALPNExt(&EXT,&ALPN); enc_ext_expt.alpn=true;// only supporting one application protocol
#endif
    addPSKModesExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    if (origin==TLS_FULL_HANDSHAKE)
    {
        addMFLExt(&EXT,4); enc_ext_expt.max_frag_length=true; // ask for max fragment length of 4096 - for some reason openssl does not accept this for PSK
    }
    addPadding(&EXT,SAL_randomByte()%16);      // add some random padding
    if (have_early_data)
    {
        addEarlyDataExt(&EXT); enc_ext_expt.early_data=true;                 // try sending client message as early data if allowed
    }
    if (external_psk)
    { // Its an external pre-shared key
        age=0;
    } else {
        time_ticket_used=(unsign32)millis();
        age=time_ticket_used-time_ticket_received; // age of ticket in milliseconds - problem for some sites which work for age=0 ??
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Ticket age= ",(char *)"%x",age,NULL);
#endif
        age+=age_obfuscator;
#if VERBOSITY >= IO_DEBUG
        logger((char *)"obfuscated age = ",(char *)"%x",age,NULL);
#endif
    }
    int extra=addPreSharedKeyExt(&EXT,age,&ETICK,hashlen);

    int ciphers[1]; ciphers[0]=cipher_suite;     // Only allow one cipher suite
// create and send Client Hello octad
    sendClientHello(client,TLS1_2,&CH,1,ciphers,&CID,&EXT,extra,&IO,false);  

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Hello sent\n",NULL,0,NULL);
#endif
    unihash tlshash;   // Universal Hash
    SAL_hashInit(hashtype,&tlshash); 
    runningHash(&CH,&tlshash); 
    runningHash(&EXT,&tlshash);
    transcriptHash(&tlshash,&HH);            // hash of Truncated clientHello

    deriveVeriferData(hashtype,&BND,&BK,&HH);
    sendBinder(client,&BL,&BND,&IO);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"BND= ",NULL,0,&BND);
    logger((char *)"Sending Binders\n",NULL,0,NULL);   // only sending one
#endif
    runningHash(&BL,&tlshash);
    transcriptHash(&tlshash,&HH);            // hash of full clientHello

    if (have_early_data)
        sendCCCS(client);

    deriveLaterSecrets(hashtype,&ES,&HH,&CETS,NULL);   // Get Client Early Traffic Secret from transcript hash and ES
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
#endif

    createCryptoContext(cipher_suite,&CETS,&K_send);  // Set Client K_send to early data keys 

// if its allowed, send client message as (encrypted) early data
    if (have_early_data)
    {
#if VERBOSITY >= IO_APPLICATION
        logger((char *)"Sending some early data\n",NULL,0,NULL);
        logger((char *)"Sending Application Message\n\n",EARLY.val,0,NULL);
#endif
        sendClientMessage(client,APPLICATION,TLS1_2,&K_send,&EARLY,NULL,&IO);
    }

// Process Server Hello
    rtn=getServerHello(client,&IO,cipher_suite,kex,&CID,&COOK,&PK,pskid);
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    logServerHello(cipher_suite,kex,pskid,&PK,&COOK);

    if (rtn.val==HANDSHAKE_RETRY)
    { // should not happen
        sendClientAlert(client,UNEXPECTED_MESSAGE,&K_send);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"No change possible as result of HRR\n",NULL,0,NULL); 
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"serverHello= ",NULL,0,&IO); 
 #endif
    if (pskid<0)
    { // Ticket rejected by Server (as out of date??)
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Preshared key rejected by server\n",NULL,0,NULL);
#endif
        sendClientAlert(client,CLOSE_NOTIFY,&K_send);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Shared Secret= ",NULL,0,&SS);
#endif
    runningHash(&IO,&tlshash);
    transcriptHash(&tlshash,&HH);       // hash of clientHello+serverHello
    deriveHandshakeSecrets(hashtype,&SS,&ES,&HH,&HS,&CTS,&STS); 
    createCryptoContext(cipher_suite,&STS,&K_recv);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Handshake Secret= ",NULL,0,&HS);
    logger((char *)"Client handshake traffic secret= ",NULL,0,&CTS);
    logger((char *)"Server handshake traffic secret= ",NULL,0,&STS);
#endif
// 1. get encrypted extensions
    OCT_kill(&IO);              // clear IO buffer

    rtn=getServerEncryptedExtensions(client,&IO,&K_recv,&tlshash,&enc_ext_expt,&enc_ext_resp);
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);

    transcriptHash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE) = ",NULL,0,&FH); 
#endif
// 2. get server finish
    rtn=getServerFinished(client,&IO,&K_recv,&tlshash,&FIN);   // Finished
    if (badResponse(client,&K_send,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcriptHash(&tlshash,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (enc_ext_resp.early_data)
    {
        sendEndOfEarlyData(client,&K_send,&tlshash,&IO);     // Should only be sent if server has accepted Early data - see encrypted extensions!
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Send End of Early Data \n",NULL,0,NULL);
#endif
    }
    transcriptHash(&tlshash,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SF+ED) = ",NULL,0,&TH); 
#endif
// Switch to handshake keys
    createCryptoContext(cipher_suite,&CTS,&K_send);

    if (!checkVeriferData(hashtype,&FIN,&STS,&FH))
    {
        sendClientAlert(client,DECRYPT_ERROR,&K_send);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Data is NOT verified\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        return 0;
    }

// create client verify data and send it to Server
    deriveVeriferData(hashtype,&CHF,&CTS,&TH);  
    sendClientFinish(client,&K_send,&tlshash,&CHF,&IO);  

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Data is verified\n",NULL,0,NULL);
    logger((char *)"Client Verify Data= ",NULL,0,&CHF); 
#endif
    transcriptHash(&tlshash,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes
    deriveApplicationSecrets(hashtype,&HS,&HH,&FH,&CTS,&STS,NULL,&RMS);  
    createCryptoContext(cipher_suite,&CTS,&K_send);
    createCryptoContext(cipher_suite,&STS,&K_recv);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client application traffic secret= ",NULL,0,&CTS);
    logger((char *)"Server application traffic secret= ",NULL,0,&STS);
#endif
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"Resumption Handshake concluded\n",NULL,0,NULL);
    if (enc_ext_resp.early_data) logger((char *)"Early data was accepted\n",NULL,0,NULL);
#endif
    if (enc_ext_resp.early_data) return 2;
    return 1;
}