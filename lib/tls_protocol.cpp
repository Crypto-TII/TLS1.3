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
	state.server_max_record=0;
    state.cipher_suite=0;//TLS_AES_128_GCM_SHA256;              // cipher suite
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

    state.favourite_group=0;							    // default key exchage group
    initTicketContext(&state.T);                            // Resumption ticket - may be added to session state
    return state;
}

#define CLEAN_FULL_STACK \
    OCT_kill(&CSK); OCT_kill(&PK); OCT_kill(&SS); OCT_kill(&CH); OCT_kill(&EXT);  OCT_kill(&SPK); \
    OCT_kill(&ES); OCT_kill(&HS); OCT_kill(&HH); OCT_kill(&FH); OCT_kill(&TH); \
    OCT_kill(&CID); OCT_kill(&COOK); OCT_kill(&SCVSIG); OCT_kill(&FIN); OCT_kill(&CHF); \
    OCT_kill(&CETS); OCT_kill(&ALPN);

// build chosen set of extensions, and assert expectations of server responses
// The User may want to change the mix of optional extensions
static void buildExtensions(TLS_session *session,octad *EXT,octad *PK,ee_status *expectations,bool resume)
{
	int groups[TLS_MAX_SUPPORTED_GROUPS];
	int nsg=SAL_groups(groups);
	int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
	int nsa=SAL_sigs(sigAlgs);
	int sigAlgsCert[TLS_MAX_SUPPORTED_SIGS];
	int nsac=SAL_sigCerts(sigAlgsCert);
    char alpn[8];
    octad ALPN={0,sizeof(alpn),alpn};         // ALPN
    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
#ifdef TLS_PROTOCOL
#if TLS_PROTOCOL == TLS_HTTP_PROTOCOL
    OCT_from_hex(&ALPN,(char *)http);
#endif
#endif

	if (resume)
	{
		nsg=1;
		groups[0]=session->favourite_group; // Only allow the group already agreed
	}

	OCT_kill(EXT);
	addServerNameExt(EXT,session->hostname); expectations->server_name=true;  // Server Name extension - acknowledgement is expected
	addSupportedGroupsExt(EXT,nsg,groups);
	addKeyShareExt(EXT,session->favourite_group,PK); // only sending one public key
#ifdef TLS_PROTOCOL
	addALPNExt(EXT,&ALPN); expectations->alpn=true; // only supporting one application protocol
#endif
	addPSKModesExt(EXT,pskMode);
	addVersionExt(EXT,tlsVersion);
#ifdef CLIENT_MAX_RECORD
	addRSLExt(EXT,CLIENT_MAX_RECORD);                     // demand a fragment size limit
#else
	addMFLExt(EXT,TLS_MAX_FRAG);  expectations->max_frag_length=true; // ask for max fragment length - server may not agree - but no harm in asking
#endif
	addPadding(EXT,SAL_randomByte()%16);  // add some random padding (because I can)

	if (!resume)
	{ // need signature related extensions for full handshake
		addSigAlgsExt(EXT,nsa,sigAlgs);
		addSigAlgsCertExt(EXT,nsac,sigAlgsCert);

	} 
}

// TLS1.3 full handshake - connect to server
static int TLS13_full(TLS_session *session)
{
    ret rtn;
    int i,pskid;
    int kex,hashtype;
	int nsa,nsc,nsg,nsac;
    bool ccs_sent=false;
    bool resumption_required=false;
    bool gotacertrequest=false;
    int nccsalgs=0;  // number of client certificate signature algorithms
    int csigAlgs[TLS_MAX_SUPPORTED_SIGS]; // acceptable client cert signature types

	int ciphers[TLS_MAX_CIPHER_SUITES];
	nsc=SAL_ciphers(ciphers);  
	int groups[TLS_MAX_SUPPORTED_GROUPS];
	nsg=SAL_groups(groups);

    char csk[TLS_MAX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octad CSK = {0, sizeof(csk), csk};
    char pk[TLS_MAX_PUB_KEY_SIZE];       // Server & Client key exchange Public Key (shared memory)
    octad PK = {0, sizeof(pk), pk};
    char ss[TLS_MAX_SHARED_SECRET_SIZE]; // key exchange Shared Secret 
    octad SS = {0, sizeof(ss), ss};      
	char spk[TLS_MAX_SERVER_PUB_KEY];    // servers public key
	octad SPK={0,sizeof(spk),spk};
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

    logger(IO_PROTOCOL,(char *)"Attempting Full Handshake\n",NULL,0,NULL);

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

    ee_status enc_ext_resp={false,false,false,false};  // encrypted extensions expectations
    ee_status enc_ext_expt={false,false,false,false};  // encrypted extensions responses
    session->favourite_group=groups[0]; // only sending one key share - so choose first in our list
//
// Generate key pair in favourite group
//
    SAL_generateKeyPair(session->favourite_group,&CSK,&PK);   
    logger(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);
    logger(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&PK);

// Client Hello
// First build our preferred mix of client Hello extensions, based on our capabililities
	buildExtensions(session,&EXT,&PK,&enc_ext_expt,false);

// create and send Client Hello octad
    sendClientHello(session,TLS1_0,&CH,false,&CID,&EXT,0,false);  

//
//
//   ----------------------------------------------------------> client Hello
//
//    
    logger(IO_DEBUG,(char *)"Client Hello sent\n",NULL,0,NULL);

// Process Server Hello response
    rtn=getServerHello(session,kex,&CID,&COOK,&PK,pskid);
//
//
//  <--------------------------------- server Hello (or helloRetryRequest?)
//
//
    if (badResponse(session,rtn)) 
    {
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// Find cipher-suite chosen by Server
    hashtype=0;
    for (i=0;i<nsc;i++)
    {
        if (session->cipher_suite==ciphers[i])
            hashtype=SAL_hashType(session->cipher_suite);
    }
    if (SAL_hashLen(hashtype)==0)
    {
        sendClientAlert(session,ILLEGAL_PARAMETER);
        logCipherSuite(session->cipher_suite);
        logger(IO_DEBUG,(char *)"Cipher_suite not valid\n",NULL,0,NULL);
        logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logCipherSuite(session->cipher_suite);
    deriveEarlySecrets(hashtype,NULL,&ES,NULL,NULL);   // Early Secret
    logger(IO_DEBUG,(char *)"Early Secret= ",NULL,0,&ES);

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
    initTranscriptHash(session);
    if (rtn.val==HANDSHAKE_RETRY)  // Was serverHello an helloRetryRequest?
    {
        runningSyntheticHash(session,&CH,&EXT); // RFC 8446 section 4.4.1
        runningHash(session,&session->IO);      // Hash of helloRetryRequest

        if (kex==session->favourite_group)
        { // its the same one I chose !?
            sendClientAlert(session,ILLEGAL_PARAMETER);
            logger(IO_DEBUG,(char *)"No change as result of HRR\n",NULL,0,NULL);   
            logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        logger(IO_DEBUG,(char *)"Server HelloRetryRequest= ",NULL,0,&session->IO);

// Repair clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions

// generate new key pair in new server selected group 
        session->favourite_group=kex;
        SAL_generateKeyPair(session->favourite_group,&CSK,&PK); 

		buildExtensions(session,&EXT,&PK,&enc_ext_expt,false);

        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR ... so send it back in an extension
        sendCCCS(session);  // send Client Cipher Change
        ccs_sent=true;

// create and send new Client Hello octad
        sendClientHello(session,TLS1_2,&CH,false,&CID,&EXT,0,true);
//
//
//  ---------------------------------------------------> Resend Client Hello
//
//
        logger(IO_DEBUG,(char *)"Client Hello re-sent\n",NULL,0,NULL);
        rtn=getServerHello(session,kex,&CID,&COOK,&PK,pskid);
//
//
//  <---------------------------------------------------------- server Hello
//
//
        if (badResponse(session,rtn)) 
        {
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        if (rtn.val==HANDSHAKE_RETRY)
        { // only one retry allowed
            logger(IO_DEBUG,(char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
            sendClientAlert(session,UNEXPECTED_MESSAGE);
            logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
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
    logger(IO_DEBUG,(char *)"Server Hello= ",NULL,0,&session->IO); 
    logServerHello(session->cipher_suite,kex,pskid,&PK,&COOK);

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
    logger(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret

    deriveHandshakeSecrets(session,&SS,&ES,&HH,&HS);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    logger(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    logger(IO_DEBUG,(char *)"Client handshake key= ",NULL,0,&(session->K_send.K));
    logger(IO_DEBUG,(char *)"Client handshake iv= ",NULL,0,&(session->K_send.IV));
    logger(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&session->STS);
    logger(IO_DEBUG,(char *)"Server handshake key= ",NULL,0,&(session->K_recv.K));
    logger(IO_DEBUG,(char *)"Server handshake iv= ",NULL,0,&(session->K_recv.IV));

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
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);
    logger(IO_DEBUG,(char *)"Encrypted Extensions Processed\n",NULL,0,NULL);
// 2. get certificate request (maybe..) and certificate chain, check it, get Server public key
    rtn=getWhatsNext(session);  // get message type
    if (badResponse(session,rtn)) 
    {
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
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        logger(IO_PROTOCOL,(char *)"Certificate Request received\n",NULL,0,NULL);
        rtn=getWhatsNext(session);  // get message type
        if (badResponse(session,rtn)) 
        {
            CLEAN_FULL_STACK
            TLS13_clean(session);
            return TLS_FAILURE;
        }
    }

    if (rtn.val!=CERTIFICATE)
    {
        sendClientAlert(session,alert_from_cause(WRONG_MESSAGE));
        logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    rtn=getCheckServerCertificateChain(session,&SPK);
//
//
//  <---------------------------------------------------------- {Certificate}
//
//
    if (badResponse(session,rtn))     
    {
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    transcriptHash(session,&HH); // HH = hash of clientHello+serverHello+encryptedExtensions+CertChain
    logger(IO_DEBUG,(char *)"Certificate Chain is valid\n",NULL,0,NULL);
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+CT) = ",NULL,0,&HH); 

// 3. get verifier signature
    int sigalg;

    rtn=getWhatsNext(session);  // get message type
    if (badResponse(session,rtn))
    {
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    if (rtn.val!=CERT_VERIFY)
    {
        sendClientAlert(session,alert_from_cause(WRONG_MESSAGE));
        logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
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
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV) = ",NULL,0,&FH);
    logger(IO_DEBUG,(char *)"Server Certificate Signature= ",NULL,0,&SCVSIG);

    logSigAlg(sigalg);
    if (!checkServerCertVerifier(sigalg,&SCVSIG,&HH,&SPK))
    {
        sendClientAlert(session,DECRYPT_ERROR);
        logger(IO_DEBUG,(char *)"Server Cert Verification failed\n",NULL,0,NULL);
        logger(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logger(IO_DEBUG,(char *)"Server Cert Verification OK\n",NULL,0,NULL);

// 4. get Server Finished
    rtn=getServerFinished(session,&FIN);
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
    if (badResponse(session,rtn))
    {
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendClientAlert(session,DECRYPT_ERROR);
        logger(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        logger(IO_DEBUG,(char *)"Full Handshake failed\n",NULL,0,NULL);
        CLEAN_FULL_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logger(IO_DEBUG,(char *)"\nServer Data is verified\n",NULL,0,NULL);
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
            logger(IO_PROTOCOL,(char *)"Client is authenticating\n",NULL,0,NULL);
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
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]) = ",NULL,0,&TH);

// create client verify data
// .... and send it to Server
    deriveVeriferData(hashtype,&CHF,&session->CTS,&TH);  
    sendClientFinish(session,&CHF);  
//
//
//  {client Finished} ----------------------------------------------------->
//
//
    logger(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish(+clientCertChain+clientCertVerify)+clientFinish
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",NULL,0,&FH);

// calculate traffic and application keys from handshake secret and transcript hashes
    deriveApplicationSecrets(session,&HS,&HH,&FH,NULL);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    logger(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    logger(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&session->STS);
    logger(IO_PROTOCOL,(char *)"FULL Handshake succeeded\n",NULL,0,NULL);
    if (resumption_required) logger(IO_PROTOCOL,(char *)"... after handshake resumption\n",NULL,0,NULL);

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
    int hashtype,kex,pskid,nsc,nsa,nsg,nsac;
    ret rtn;
    char es[TLS_MAX_HASH];               // Early Secret
    octad ES = {0,sizeof(es),es};
    char hs[TLS_MAX_HASH];               // Handshake Secret
    octad HS = {0,sizeof(hs),hs};
    char ss[TLS_MAX_SHARED_SECRET_SIZE];
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

    unsign32 time_ticket_received,time_ticket_used;
    int origin,lifetime=0;
    unsign32 age,age_obfuscator=0;
    unsign32 max_early_data=0;
    bool have_early_data=true;       // Hope to send client message as early data
    bool external_psk=false;
    ee_status enc_ext_resp={false,false,false,false};  // encrypted extensions expectations
    ee_status enc_ext_expt={false,false,false,false};  // encrypted extensions responses

// Extract Ticket parameters
    lifetime=session->T.lifetime;
    age_obfuscator=session->T.age_obfuscator;
    max_early_data=session->T.max_early_data;
    OCT_copy(&PSK,&session->T.PSK);
    time_ticket_received=session->T.birth;
    session->cipher_suite=session->T.cipher_suite;
    session->favourite_group=session->T.favourite_group;
    origin=session->T.origin;

    logger(IO_PROTOCOL,(char *)"Attempting Resumption Handshake\n",NULL,0,NULL);
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
    logger(IO_DEBUG,(char *)"PSK= ",NULL,0,&PSK); 
    logger(IO_DEBUG,(char *)"Binder Key= ",NULL,0,&BK); 
    logger(IO_DEBUG,(char *)"Early Secret= ",NULL,0,&ES);

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
    SAL_generateKeyPair(session->favourite_group,&CSK,&PK);
    logger(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);  
    logger(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&PK);  

// Client Hello
// First build standard client Hello extensions

	buildExtensions(session,&EXT,&PK,&enc_ext_expt,true);	
	
    if (have_early_data)
    {
        addEarlyDataExt(&EXT); enc_ext_expt.early_data=true;                 // try sending client message as early data if allowed
    }
    age=0;
    if (!external_psk)
    { // Its NOT an external pre-shared key
        time_ticket_used=(unsign32)millis();
        age=time_ticket_used-time_ticket_received; // age of ticket in milliseconds - problem for some sites which work for age=0 ??
        logger(IO_DEBUG,(char *)"Ticket age= ",(char *)"%x",age,NULL);
        age+=age_obfuscator;
        logger(IO_DEBUG,(char *)"obfuscated age = ",(char *)"%x",age,NULL);
    }

    int extra=addPreSharedKeyExt(&EXT,age,&session->T.TICK,SAL_hashLen(hashtype));

// create and send Client Hello octad
    sendClientHello(session,TLS1_2,&CH,true,&CID,&EXT,extra,false);  
//
//
//   ----------------------------------------------------------> client Hello
//
//
    runningHash(session,&CH); 
    runningHash(session,&EXT);

    transcriptHash(session,&HH);            // HH = hash of Truncated clientHello
    logger(IO_DEBUG,(char *)"Client Hello sent\n",NULL,0,NULL);

    deriveVeriferData(hashtype,&BND,&BK,&HH);
    sendBinder(session,&BL,&BND);
    runningHash(session,&BL);
    transcriptHash(session,&HH);            // HH = hash of full clientHello

    logger(IO_DEBUG,(char *)"BND= ",NULL,0,&BND);
    logger(IO_DEBUG,(char *)"Sending Binders\n",NULL,0,NULL);   // only sending one

    if (have_early_data)
        sendCCCS(session);

    deriveLaterSecrets(hashtype,&ES,&HH,&CETS,NULL);   // Get Client Early Traffic Secret from transcript hash and ES
    logger(IO_DEBUG,(char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
    createSendCryptoContext(session,&CETS);
// if its allowed, send client message as (encrypted!) early data
    if (have_early_data)
    {
        logger(IO_APPLICATION,(char *)"Sending some early data\n",NULL,0,NULL);
        sendClientMessage(session,APPLICATION,TLS1_2,EARLY,NULL);
//
//
//   ----------------------------------------------------------> (Early Data)
//
//
    }

// Process Server Hello
    rtn=getServerHello(session,kex,&CID,&COOK,&PK,pskid);
//
//
//  <---------------------------------------------------------- server Hello
//
//
    runningHash(session,&session->IO); // Hashing Server Hello
    transcriptHash(session,&HH);       // HH = hash of clientHello+serverHello

    if (pskid<0)
    { // Ticket rejected by Server (as out of date??)
        logger(IO_PROTOCOL,(char *)"Ticket rejected by server\n",NULL,0,NULL);
        sendClientAlert(session,CLOSE_NOTIFY);
        logger(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

	if (pskid>0)
	{ // pskid out-of-range (only one allowed)
        sendClientAlert(session,ILLEGAL_PARAMETER);
        logger(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
	}

    if (badResponse(session,rtn)) 
    {
        sendClientAlert(session,CLOSE_NOTIFY);
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logServerHello(session->cipher_suite,kex,pskid,&PK,&COOK);

    if (rtn.val==HANDSHAKE_RETRY)
    { // should not happen
        sendClientAlert(session,UNEXPECTED_MESSAGE);
        logger(IO_DEBUG,(char *)"No change possible as result of HRR\n",NULL,0,NULL); 
        logger(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logger(IO_DEBUG,(char *)"serverHello= ",NULL,0,&session->IO); 

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    SAL_generateSharedSecret(kex,&CSK,&PK,&SS);
    logger(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);

    deriveHandshakeSecrets(session,&SS,&ES,&HH,&HS); 
    createRecvCryptoContext(session,&session->STS);

    logger(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&HS);
    logger(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    logger(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&session->STS);

// 1. get encrypted extensions
    rtn=getServerEncryptedExtensions(session,&enc_ext_expt,&enc_ext_resp);
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
    if (badResponse(session,rtn)) 
    {
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE) = ",NULL,0,&FH); 

// 2. get server finish
    rtn=getServerFinished(session,&FIN);   // Finished
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
    if (badResponse(session,rtn)) 
    {
        CLEAN_RESUMPTION_STACK
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcriptHash(session,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (enc_ext_resp.early_data)
    {
        sendEndOfEarlyData(session);     // Should only be sent if server has accepted Early data - see encrypted extensions!
        logger(IO_DEBUG,(char *)"Send End of Early Data \n",NULL,0,NULL);
    }
    transcriptHash(session,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
    logger(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SF+ED) = ",NULL,0,&TH); 

// Switch to handshake keys
    createSendCryptoContext(session,&session->CTS);
    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendClientAlert(session,DECRYPT_ERROR);
        logger(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        logger(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
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
    logger(IO_DEBUG,(char *)"Server Data is verified\n",NULL,0,NULL);
    logger(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 

    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session
    deriveApplicationSecrets(session,&HS,&HH,&FH,NULL);  
    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    logger(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    logger(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&session->STS);
    logger(IO_PROTOCOL,(char *)"RESUMPTION Handshake succeeded\n",NULL,0,NULL);

    CLEAN_RESUMPTION_STACK
    OCT_kill(&session->IO);  // clean up IO buffer

    if (enc_ext_resp.early_data)
    {
        logger(IO_PROTOCOL,(char *)"Application Message accepted as Early Data\n\n",EARLY->val,0,NULL);
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
        logger(IO_PROTOCOL,(char *)"Resumption Ticket not found or invalid\n",NULL,0,NULL);
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
    logger(IO_APPLICATION,(char *)"Sending Application Message\n\n",GET->val,0,NULL);
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
        logger(IO_PROTOCOL,(char *)"Waiting for Server input \n",NULL,0,NULL);
        OCT_kill(&session->IO); ptr=0;
        type=getServerFragment(session);  // get first fragment to determine type
        if (type<0)
            return type;   // its an error
        if (type==TIMED_OUT)
        {
            logger(IO_PROTOCOL,(char *)"TIME_OUT\n",NULL,0,NULL);
            return TIMED_OUT;
        }
        if (type==HSHAKE)
        {
            while (1)
            {
                r=parseIntorPull(session,1,ptr); nb=r.val; if (r.err) return r.err;
                r=parseIntorPull(session,3,ptr); len=r.val; if (r.err) return r.err;   // message length
                switch (nb)
                {
                case TICKET :   // keep last ticket
                    r=parseoctadorPullptr(session,&TICK,len,ptr);    // just copy out pointer to this
                    nticks++;
                    rtn=parseTicket(&TICK,(unsign32)millis(),&session->T);       // extract into ticket structure T, and keep for later use  
                    if (rtn==BAD_TICKET) {
                        session->T.valid=false;
                        logger(IO_PROTOCOL,(char *)"Got a bad ticket ",NULL,0,NULL);
                    } else {
                        session->T.cipher_suite=session->cipher_suite;
                        session->T.favourite_group=session->favourite_group;
                        session->T.valid=true;
                        logger(IO_PROTOCOL,(char *)"Got a ticket with lifetime (minutes)= ",(char *)"%d",session->T.lifetime/60,NULL);
                    }

                    if (ptr==session->IO.len) fin=true; // record finished
                    if (fin) break;
                    continue;

               case KEY_UPDATE :
                    if (len!=1)
                    {
                        logger(IO_PROTOCOL,(char *)"Something wrong\n",NULL,0,NULL);
                        return BAD_RECORD;
                    }
                    r=parseIntorPull(session,1,ptr); kur=r.val; if (r.err) break;
                    if (kur==0)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);  // reset record number
                        logger(IO_PROTOCOL,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (kur==1)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);
                        logger(IO_PROTOCOL,(char *)"Key update notified - client should do the same (?) \n",NULL,0,NULL);
                        logger(IO_PROTOCOL,(char *)"KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (ptr==session->IO.len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
                    logger(IO_PROTOCOL,(char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
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
            logger(IO_PROTOCOL,(char *)"*** Alert received - ",NULL,0,NULL);
            logAlert(session->IO.val[1]);
            return type;    // Alert received
        }
    }

    if (session->T.valid)
    { // if ticket received, recover PSK
        recoverPSK(session); // recover PSK using NONCE and RMS, and store it with ticket
        session->T.origin=TLS_FULL_HANDSHAKE;
    } else {
        logger(IO_PROTOCOL,(char *)"No ticket provided \n",NULL,0,NULL);
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
