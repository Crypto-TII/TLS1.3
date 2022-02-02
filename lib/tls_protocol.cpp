//
// Main TLS1.3 protocol
//

#include "tls_protocol.h"

static const char *http= (const char *)"687474702f312e31"; // http/1.1

// Initialise TLS 1.3 session state
TLS_session TLS13_start(Socket *sockptr,char *hostname)
{
    TLS_session state;
    state.sockptr=sockptr;                                  // pointer to socket
    strcpy(state.hostname,hostname);                        // server to connection with
    state.session_status=TLS13_DISCONNECTED;
    state.cipher_suite=TLS_AES_128_GCM_SHA256;              // default cipher suite
    state.CPB.nsg=SAL_groups(state.CPB.supportedGroups);    // Get supported Key Exchange Groups in order of preference
    state.CPB.nsc=SAL_ciphers(state.CPB.ciphers);           // Get supported Cipher Suits
    state.CPB.nsa=SAL_sigs(state.CPB.sigAlgs);              // Get supported TLS1.3 signing algorithms 
    state.CPB.nsac=SAL_sigCerts(state.CPB.sigAlgsCert);     // Get supported Certificate signing algorithms 
    initCryptoContext(&state.K_send);                       // Transmission key
    initCryptoContext(&state.K_recv);                       // Reception key

	state.RMS={0,TLS_MAX_HASH,state.rms};					// Resumption Master secret
	state.STS={0,TLS_MAX_HASH,state.sts};					// Server traffic secret
	state.CTS={0,TLS_MAX_HASH,state.cts};					// Client traffic secret

#ifdef IOBUFF_FROM_HEAP
    state.IO= {0,TLS_MAX_IO_SIZE,(char *)malloc(TLS_MAX_IO_SIZE)};  // main input/output buffer
#else
	state.IO={0,TLS_MAX_IO_SIZE,state.io};
#endif

    state.favourite_group=state.CPB.supportedGroups[0];     // favourite key exchange group - may be changed on handshake retry
    initTicketContext(&state.T);                            // Resumption ticket - may be added to session state
    return state;
}

#define CLEAN_FULL_STACK \
    OCT_kill(&CSK); OCT_kill(&PK); OCT_kill(&SS); OCT_kill(&CH); OCT_kill(&EXT); \
    OCT_kill(&ES); OCT_kill(&HS); OCT_kill(&HH); OCT_kill(&FH); OCT_kill(&TH); \
    OCT_kill(&CID); OCT_kill(&COOK); OCT_kill(&SCVSIG); OCT_kill(&FIN); OCT_kill(&CHF); \
    OCT_kill(&CETS); OCT_kill(&ALPN);

// TLS1.3 full handshake - connect to server
static int TLS13_full(TLS_session *session)
{
    ret rtn;
    int i,pskid;
    int cs_hrr,kex,hashtype;
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

#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Attempting Full Handshake\n",NULL,0,NULL);
#endif

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
    
    session->favourite_group=session->CPB.supportedGroups[0]; // only sending one key share in our favourite group
//
// Generate key pair in favourite group
//
    SAL_generateKeyPair(session->favourite_group,&CSK,&PK);

#if VERBOSITY >= IO_DEBUG    
    logger((char *)"Private key= ",NULL,0,&CSK);
    logger((char *)"Client Public key= ",NULL,0,&PK);
#endif

// Client Hello
// First build our preferred mix of client Hello extensions, based on our capabililities
    addServerNameExt(&EXT,session->hostname); enc_ext_expt.server_name=true;  // Server Name extension - acknowledgement is expected
    addSupportedGroupsExt(&EXT,session->CPB.nsg,session->CPB.supportedGroups);
    addSigAlgsExt(&EXT,session->CPB.nsa,session->CPB.sigAlgs);
    addSigAlgsCertExt(&EXT,session->CPB.nsac,session->CPB.sigAlgsCert);
    addKeyShareExt(&EXT,session->favourite_group,&PK); // only sending one public key
#ifdef TLS_PROTOCOL
    addALPNExt(&EXT,&ALPN); enc_ext_expt.alpn=true; // only supporting one application protocol
#endif
    addPSKModesExt(&EXT,pskMode);
    addVersionExt(&EXT,tlsVersion);
    addMFLExt(&EXT,4);  enc_ext_expt.max_frag_length=true; // ask for smaller max fragment length of 4096 - server may not agree - but no harm in asking
    addPadding(&EXT,SAL_randomByte()%16);  // add some random padding (because I can)

// create and send Client Hello octad
    sendClientHello(session,TLS1_0,&CH,session->CPB.nsc,session->CPB.ciphers,&CID,&EXT,0,false);  

//
//
//   ----------------------------------------------------------> client Hello
//
//

#if VERBOSITY >= IO_DEBUG     
    logger((char *)"Client Hello sent\n",NULL,0,NULL);
#endif

// Process Server Hello response
    rtn=getServerHello(session,session->cipher_suite,kex,&CID,&COOK,&PK,pskid);
//
//
//  <--------------------------------- server Hello (or helloRetryRequest?)
//
//

    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// Find cipher-suite chosen by Server
    hashtype=0;
    for (i=0;i<session->CPB.nsc;i++)
    {
        if (session->cipher_suite==session->CPB.ciphers[i])
            hashtype=SAL_hashType(session->cipher_suite);
    }
    if (SAL_hashLen(hashtype)==0)
    {
        sendClientAlert(session,ILLEGAL_PARAMETER);
        logCipherSuite(session->cipher_suite);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Cipher_suite not valid\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logCipherSuite(session->cipher_suite);

    deriveEarlySecrets(hashtype,NULL,&ES,NULL,NULL);   // Early Secret

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Early Secret= ",NULL,0,&ES);
#endif

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
    initTranscriptHash(session);
    if (rtn.val==HANDSHAKE_RETRY)  // Was serverHello an helloRetryRequest?
    {
        runningSyntheticHash(session,&CH,&EXT); // RFC 8446 section 4.4.1
        runningHash(session,&session->IO);     // Hash of helloRetryRequest

        if (kex==session->favourite_group)
        { // its the same one I chose !?
            sendClientAlert(session,ILLEGAL_PARAMETER);
#if VERBOSITY >= IO_DEBUG
            logger((char *)"No change as result of HRR\n",NULL,0,NULL);   
#endif
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server HelloRetryRequest= ",NULL,0,&session->IO);
#endif

// Repair clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions
        OCT_kill(&EXT);
        addServerNameExt(&EXT,session->hostname); 
        addSupportedGroupsExt(&EXT,session->CPB.nsg,session->CPB.supportedGroups);
        addSigAlgsExt(&EXT,session->CPB.nsa,session->CPB.sigAlgs);
        addSigAlgsCertExt(&EXT,session->CPB.nsac,session->CPB.sigAlgsCert);
// generate new key pair in new server selected group 
        session->favourite_group=kex;
        SAL_generateKeyPair(session->favourite_group,&CSK,&PK); 
        addKeyShareExt(&EXT,session->favourite_group,&PK);  // Public Key Share in new group
#ifdef TLS_PROTOCOL
        addALPNExt(&EXT,&ALPN); // only supporting one application protocol
#endif
        addPSKModesExt(&EXT,pskMode);
        addVersionExt(&EXT,tlsVersion);
        addMFLExt(&EXT,4);                      // ask for max fragment length of 4096
        addPadding(&EXT,SAL_randomByte()%16);  // add some random padding
        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR
        sendCCCS(session);  // send Client Cipher Change
        ccs_sent=true;

// create and send new Client Hello octad
        sendClientHello(session,TLS1_2,&CH,session->CPB.nsc,session->CPB.ciphers,&CID,&EXT,0,true);
//
//
//  ---------------------------------------------------> Resend Client Hello
//
//

#if VERBOSITY >= IO_DEBUG
        logger((char *)"Client Hello re-sent\n",NULL,0,NULL);
#endif
        rtn=getServerHello(session,cs_hrr,kex,&CID,&COOK,&PK,pskid);
//
//
//  <---------------------------------------------------------- server Hello
//
//
        if (badResponse(session,rtn)) 
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        if (rtn.val==HANDSHAKE_RETRY)
        { // only one retry allowed
#if VERBOSITY >= IO_DEBUG
            logger((char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
#endif
            sendClientAlert(session,UNEXPECTED_MESSAGE);
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        if (cs_hrr!=session->cipher_suite)
        { // Server cannot change cipher_suite at this stage
#if VERBOSITY >= IO_DEBUG
            logger((char *)"Server selected different cipher suite\n",NULL,0,NULL); 
#endif
            sendClientAlert(session,ILLEGAL_PARAMETER); 
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        resumption_required=true;
    }
// Hash Transcript the Hellos 
    runningHash(session,&CH);
    runningHash(session,&EXT);
    runningHash(session,&session->IO);  // Hashing Server Hello
    transcriptHash(session,&HH);        // HH = hash of clientHello+serverHello

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Hello= ",NULL,0,&session->IO); 
#endif
    logServerHello(session->cipher_suite,kex,pskid,&PK,&COOK);

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Shared Secret= ",NULL,0,&SS);
#endif

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret

    deriveHandshakeSecrets(session,&SS,&ES,&HH,&HS);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Handshake Secret= ",NULL,0,&HS);
    logger((char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    logger((char *)"Client handshake key= ",NULL,0,&(session->K_send.K));
    logger((char *)"Client handshake iv= ",NULL,0,&(session->K_send.IV));
    logger((char *)"Server handshake traffic secret= ",NULL,0,&session->STS);
    logger((char *)"Server handshake key= ",NULL,0,&(session->K_recv.K));
    logger((char *)"Server handshake iv= ",NULL,0,&(session->K_recv.IV));
#endif
// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).

// 1. get encrypted extensions
    rtn=getServerEncryptedExtensions(session,&enc_ext_expt,&enc_ext_resp);   
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Encrypted Extensions Processed\n",NULL,0,NULL);
#endif
// 2. get certificate request (maybe..) and certificate chain, check it, get Server public key
    rtn=getWhatsNext(session);  // get message type
    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

    if (rtn.val==CERT_REQUEST)
    { // 2a. optional certificate request received
        gotacertrequest=true;
        rtn=getCertificateRequest(session,nccsalgs,csigAlgs);
//
//
//  <---------------------------------------------------- {Certificate Request}
//
//
        if (badResponse(session,rtn))
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }

#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Certificate Request received\n",NULL,0,NULL);
#endif
        rtn=getWhatsNext(session);  // get message type
        if (badResponse(session,rtn)) 
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
    }

    if (rtn.val!=CERTIFICATE)
    {
        sendClientAlert(session,alert_from_cause(WRONG_MESSAGE));
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    rtn=getCheckServerCertificateChain(session,&SS);
//
//
//  <---------------------------------------------------------- {Certificate}
//
//
    if (badResponse(session,rtn))     
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    transcriptHash(session,&HH); // HH = hash of clientHello+serverHello+encryptedExtensions+CertChain
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Certificate Chain is valid\n",NULL,0,NULL);
    logger((char *)"Transcript Hash (CH+SH+EE+CT) = ",NULL,0,&HH); 
#endif
// 3. get verifier signature
    int sigalg;

    rtn=getWhatsNext(session);  // get message type
    if (badResponse(session,rtn))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    if (rtn.val!=CERT_VERIFY)
    {
        sendClientAlert(session,alert_from_cause(WRONG_MESSAGE));
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    rtn=getServerCertVerify(session,&SCVSIG,sigalg);
//
//
//  <---------------------------------------------------- {Certificate Verify}
//
//
    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV) = ",NULL,0,&FH);
    logger((char *)"Server Certificate Signature= ",NULL,0,&SCVSIG);
#endif
    logSigAlg(sigalg);
    if (!checkServerCertVerifier(sigalg,&SCVSIG,&HH,&SS))
    {
        sendClientAlert(session,DECRYPT_ERROR);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Cert Verification failed\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Cert Verification OK\n",NULL,0,NULL);
#endif
// 4. get Server Finished
    rtn=getServerFinished(session,&FIN);
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
    if (badResponse(session,rtn))
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendClientAlert(session,DECRYPT_ERROR);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Data is NOT verified\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Full Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"\nServer Data is verified\n",NULL,0,NULL);
#endif
    if (!ccs_sent)
        sendCCCS(session);  // send Client Cipher Change (if not already sent)
    transcriptHash(session,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

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
            sendClientCertificateChain(session,&CLIENT_CERTCHAIN);
//
//
//  {client Certificate} ---------------------------------------------------->
//
//
            transcriptHash(session,&TH);
            createClientCertVerifier(kind,&TH,&CLIENT_KEY,&CCVSIG);      
            sendClientCertVerify(session,kind,&CCVSIG);
//
//
//  {Certificate Verify} ---------------------------------------------------->
//
//
        } else { // No, I can't - send a null cert
            sendClientCertificateChain(session,NULL);
        }
#else
        sendClientCertificateChain(session,NULL);
#endif
        transcriptHash(session,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish+clientCertChain+clientCertVerify
    } else {
        OCT_copy(&TH,&HH);
    }

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = ",NULL,0,&TH);
#endif

// create client verify data
// .... and send it to Server
    deriveVeriferData(hashtype,&CHF,&session->CTS,&TH);  
    sendClientFinish(session,&CHF);  
//
//
//  {client Finished} ----------------------------------------------------->
//
//
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Verify Data= ",NULL,0,&CHF); 
#endif
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish(+clientCertChain+clientCertVerify)+clientFinish

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",NULL,0,&FH);
#endif

// calculate traffic and application keys from handshake secret and transcript hashes
    deriveApplicationSecrets(session,&HS,&HH,&FH,NULL);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    logger((char *)"Server application traffic secret= ",NULL,0,&session->STS);
#endif
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"FULL Handshake succeeded\n",NULL,0,NULL);
    if (resumption_required) logger((char *)"... after handshake resumption\n",NULL,0,NULL);
#endif

    CLEAN_FULL_STACK
    OCT_kill(&session->IO);  // clean up IO buffer

    if (resumption_required) return TLS_RESUMPTION_REQUIRED;
    return TLS_SUCCESS;
}

#define CLEAN_RESUMPTION_STACK \
    OCT_kill(&ES); OCT_kill(&HS); OCT_kill(&SS); OCT_kill(&CSK); OCT_kill(&PK); \
    OCT_kill(&CH); OCT_kill(&EXT); OCT_kill(&HH); OCT_kill(&FH); OCT_kill(&TH); \
    OCT_kill(&FIN); OCT_kill(&CHF); OCT_kill(&CETS); OCT_kill(&CID); OCT_kill(&COOK); \
    OCT_kill(&BND); OCT_kill(&BL); OCT_kill(&PSK); OCT_kill(&BK); OCT_kill(&ALPN);

// TLS1.3 fast resumption handshake (0RTT and 1RTT)
// EARLY - First message from Client to Server (should ideally be sent as early data!)
static int TLS13_resume(TLS_session *session,octad *EARLY)
{
    int hashtype,kex,pskid;
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
    char fin[TLS_MAX_HASH];
    octad FIN={0,sizeof(fin),fin};      // Server's finish message
    char chf[TLS_MAX_HASH];                           
    octad CHF={0,sizeof(chf),chf};      // client verify
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
    octad PSK={0,sizeof(psk),psk};      // Pre-shared key
    char bk[TLS_MAX_HASH];
    octad BK={0,sizeof(bk),bk};         // Binder key
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
    lifetime=session->T.lifetime;
    age_obfuscator=session->T.age_obfuscator;
    max_early_data=session->T.max_early_data;
    OCT_copy(&PSK,&session->T.PSK);
    time_ticket_received=session->T.birth;
    session->cipher_suite=session->T.cipher_suite;
    session->favourite_group=session->T.favourite_group;
    origin=session->T.origin;

#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Attempting Resumption Handshake\n",NULL,0,NULL);
#endif

    logTicket(&session->T); // lifetime,age_obfuscator,max_early_data,&NONCE,&ETICK);

    if (max_early_data==0 || EARLY==NULL)
        have_early_data=false;      // early data not allowed - or I don't have any

// Generate Early secret and Binder Key from PSK

    hashtype=SAL_hashType(session->cipher_suite);
    initTranscriptHash(session);

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
    SAL_generateKeyPair(session->favourite_group,&CSK,&PK);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Private key= ",NULL,0,&CSK);  
    logger((char *)"Client Public key= ",NULL,0,&PK);  
#endif

// Client Hello
// First build client Hello extensions
    OCT_kill(&EXT);
    addServerNameExt(&EXT,session->hostname); enc_ext_expt.server_name=true;
    int groups[1]; groups[0]=session->favourite_group;    // Only allow one group
    addSupportedGroupsExt(&EXT,1,groups);  
// Signature algorithms not needed for resumption, so smaller clientHello
    addKeyShareExt(&EXT,session->favourite_group,&PK); // only sending one public key 
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

    int extra=addPreSharedKeyExt(&EXT,age,&session->T.TICK,SAL_hashLen(hashtype));
    int ciphers[1]; ciphers[0]=session->cipher_suite;     // Only allow one cipher suite
// create and send Client Hello octad
    sendClientHello(session,TLS1_2,&CH,1,ciphers,&CID,&EXT,extra,false);  
//
//
//   ----------------------------------------------------------> client Hello
//
//
    runningHash(session,&CH); 
    runningHash(session,&EXT);

    transcriptHash(session,&HH);            // HH = hash of Truncated clientHello

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Hello sent\n",NULL,0,NULL);
#endif

    deriveVeriferData(hashtype,&BND,&BK,&HH);
    sendBinder(session,&BL,&BND);
    runningHash(session,&BL);
    transcriptHash(session,&HH);            // HH = hash of full clientHello

#if VERBOSITY >= IO_DEBUG
    logger((char *)"BND= ",NULL,0,&BND);
    logger((char *)"Sending Binders\n",NULL,0,NULL);   // only sending one
#endif

    if (have_early_data)
        sendCCCS(session);

    deriveLaterSecrets(hashtype,&ES,&HH,&CETS,NULL);   // Get Client Early Traffic Secret from transcript hash and ES
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
#endif
    createSendCryptoContext(session,&CETS);
// if its allowed, send client message as (encrypted!) early data
    if (have_early_data)
    {
#if VERBOSITY >= IO_APPLICATION
        logger((char *)"Sending some early data\n",NULL,0,NULL);
#endif
        sendClientMessage(session,APPLICATION,TLS1_2,EARLY,NULL);
//
//
//   ----------------------------------------------------------> (Early Data)
//
//
    }

// Process Server Hello
    rtn=getServerHello(session,session->cipher_suite,kex,&CID,&COOK,&PK,pskid);
//
//
//  <---------------------------------------------------------- server Hello
//
//
    runningHash(session,&session->IO); // Hashing Server Hello
    transcriptHash(session,&HH);       // HH = hash of clientHello+serverHello

    if (pskid<0)
    { // Ticket rejected by Server (as out of date??)
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Ticket rejected by server\n",NULL,0,NULL);
#endif
        sendClientAlert(session,CLOSE_NOTIFY);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

	if (pskid>0)
	{ // pskid out-of-range (only one allowed)
        sendClientAlert(session,ILLEGAL_PARAMETER);
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
	}

    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        sendClientAlert(session,CLOSE_NOTIFY);
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logServerHello(session->cipher_suite,kex,pskid,&PK,&COOK);

    if (rtn.val==HANDSHAKE_RETRY)
    { // should not happen
        sendClientAlert(session,UNEXPECTED_MESSAGE);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"No change possible as result of HRR\n",NULL,0,NULL); 
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
#if VERBOSITY >= IO_DEBUG
    logger((char *)"serverHello= ",NULL,0,&session->IO); 
 #endif

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Shared Secret= ",NULL,0,&SS);
#endif

    deriveHandshakeSecrets(session,&SS,&ES,&HH,&HS); 
    createRecvCryptoContext(session,&session->STS);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Handshake Secret= ",NULL,0,&HS);
    logger((char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    logger((char *)"Server handshake traffic secret= ",NULL,0,&session->STS);
#endif
// 1. get encrypted extensions
    rtn=getServerEncryptedExtensions(session,&enc_ext_expt,&enc_ext_resp);
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);

    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE) = ",NULL,0,&FH); 
#endif
// 2. get server finish
    rtn=getServerFinished(session,&FIN);   // Finished
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
    if (badResponse(session,rtn)) 
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcriptHash(session,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (enc_ext_resp.early_data)
    {
        sendEndOfEarlyData(session);     // Should only be sent if server has accepted Early data - see encrypted extensions!
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Send End of Early Data \n",NULL,0,NULL);
#endif
    }
    transcriptHash(session,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Transcript Hash (CH+SH+EE+SF+ED) = ",NULL,0,&TH); 
#endif
// Switch to handshake keys
    createSendCryptoContext(session,&session->CTS);
    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendClientAlert(session,DECRYPT_ERROR);
#if VERBOSITY >= IO_DEBUG
        logger((char *)"Server Data is NOT verified\n",NULL,0,NULL);
#endif
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Handshake failed\n",NULL,0,NULL);
#endif
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// create client verify data and send it to Server
    deriveVeriferData(hashtype,&CHF,&session->CTS,&TH);  
    sendClientFinish(session,&CHF);  
//
//
//  {client Finished} ----------------------------------------------------->
//
//
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Server Data is verified\n",NULL,0,NULL);
    logger((char *)"Client Verify Data= ",NULL,0,&CHF); 
#endif
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session
    deriveApplicationSecrets(session,&HS,&HH,&FH,NULL);  
    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

#if VERBOSITY >= IO_DEBUG
    logger((char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    logger((char *)"Server application traffic secret= ",NULL,0,&session->STS);
#endif
#if VERBOSITY >= IO_PROTOCOL
    logger((char *)"RESUMPTION Handshake succeeded\n",NULL,0,NULL);
#endif
    CLEAN_RESUMPTION_STACK
    OCT_kill(&session->IO);  // clean up IO buffer

    if (enc_ext_resp.early_data)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Application Message accepted as Early Data\n\n",EARLY->val,0,NULL);
#endif
        return TLS_EARLY_DATA_ACCEPTED;
    }
    return TLS_SUCCESS;
}

// connect to server
// first try resumption if session has a good ticket attached
bool TLS13_connect(TLS_session *session,octad *EARLY)
{
    int rtn=0;
    bool early_went=false;
    if (ticket_still_good(&session->T))
    { // have a good ticket? Try it.
        rtn=TLS13_resume(session,EARLY);
        if (rtn==TLS_EARLY_DATA_ACCEPTED) early_went=true;
    } else {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Resumption Ticket not found or invalid\n",NULL,0,NULL);
#endif
        rtn=TLS13_full(session);
    }
    initTicketContext(&session->T); // clear out any ticket
    
    if (rtn==0)  // failed to connect
        return false;
    
    if (!early_went && EARLY!=NULL)
        TLS13_send(session,EARLY);  // didn't go early, so send it now

    return true;   // exiting with live session, ready to receive fresh ticket
}

// send a message post-handshake
void TLS13_send(TLS_session *state,octad *GET)
{
#if VERBOSITY >= IO_APPLICATION
    logger((char *)"Sending Application Message\n\n",GET->val,0,NULL);
#endif
    sendClientMessage(state,APPLICATION,TLS1_2,GET,NULL);
}

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// For example could include a ticket. Also receiving key K_recv might be updated.

int TLS13_recv(TLS_session *session,octad *REC)
{
    ret r;
    int nce,nb,len,te,type,nticks,kur,rtn,ptr=0;
    bool fin=false;
    unsign32 time_ticket_received;
    octad TICK;  // Ticket raw data
    TICK.len=0;

    nticks=0; // number of tickets received
    while (1)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Waiting for Server input \n",NULL,0,NULL);
#endif
        OCT_kill(&session->IO); ptr=0;
        type=getServerFragment(session);  // get first fragment to determine type
        if (type<0)
            return type;   // its an error
        if (type==TIMED_OUT)
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"TIME_OUT\n",NULL,0,NULL);
#endif
            return TIMED_OUT;
        }
        if (type==HSHAKE)
        {
            while (1)
            {
                r=parseByteorPull(session,ptr); nb=r.val; if (r.err) return r.err;
                r=parseInt24orPull(session,ptr); len=r.val; if (r.err) return r.err;   // message length
                switch (nb)
                {
                case TICKET :   // keep last ticket
                    r=parseoctadorPullptr(session,&TICK,len,ptr);    // just copy out pointer to this
                    nticks++;
                    rtn=parseTicket(&TICK,(unsign32)millis(),&session->T);       // extract into ticket structure T, and keep for later use  
                    if (rtn==BAD_TICKET) {
                        session->T.valid=false;
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Got a bad ticket ",NULL,0,NULL);
#endif
                    } else {
                        session->T.cipher_suite=session->cipher_suite;
                        session->T.favourite_group=session->favourite_group;
                        session->T.valid=true;
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Got a ticket with lifetime (minutes)= ",(char *)"%d",session->T.lifetime/60,NULL);
#endif
                    }

                    if (ptr==session->IO.len) fin=true; // record finished
                    if (fin) break;
                    continue;

               case KEY_UPDATE :
                    if (len!=1)
                    {
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Something wrong\n",NULL,0,NULL);
#endif
                        return BAD_RECORD;
                    }
                    r=parseByteorPull(session,ptr); kur=r.val; if (r.err) break;
                    if (kur==0)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);  // reset record number
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"KEYS UPDATED\n",NULL,0,NULL);
#endif
                    }
                    if (kur==1)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);
#if VERBOSITY >= IO_PROTOCOL
                        logger((char *)"Key update notified - client should do the same (?) \n",NULL,0,NULL);
                        logger((char *)"KEYS UPDATED\n",NULL,0,NULL);
#endif
                    }
                    if (ptr==session->IO.len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
#if VERBOSITY >= IO_PROTOCOL
                    logger((char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
#endif
                    fin=true;
                    break;            
                }
                if (r.err) return r.err;
                if (fin) break;
            }
        }
        if (type==APPLICATION)
        { // application data received - return it
            OCT_copy(REC,&session->IO);
            break;
        }
        if (type==ALERT)
        {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"*** Alert received - ",NULL,0,NULL);
            logAlert(session->IO.val[1]);
#endif
            return type;    // Alert received
        }
    }

    if (session->T.valid)
    { // if ticket received, recover PSK
        recoverPSK(session); // recover PSK using NONCE and RMS, and store it with ticket
        session->T.origin=TLS_FULL_HANDSHAKE;
    } else {
#if VERBOSITY >= IO_PROTOCOL
            logger((char *)"No ticket provided \n",NULL,0,NULL);
#endif
    }

    return type;
}

// clean up buffers, kill crypto keys
void TLS13_clean(TLS_session *session)
{
    OCT_kill(&session->IO);
    OCT_kill(&session->CTS);
    OCT_kill(&session->STS);
    OCT_kill(&session->RMS);
    initCryptoContext(&session->K_send);
    initCryptoContext(&session->K_recv);
}

void TLS13_end(TLS_session *session)
{
    TLS13_clean(session);
    endTicketContext(&session->T);
#ifdef IOBUFF_FROM_HEAP
    free(session->IO.val);
#endif
}
