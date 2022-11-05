//
// Main TLS1.3 protocol
//

#include "tls_protocol.h"

// Initialise TLS 1.3 session state
TLS_session TLS13_start(Socket *sockptr,char *hostname)
{
    TLS_session state;
    state.sockptr=sockptr;                                  // pointer to socket
    strcpy(state.hostname,hostname);                        // server to connection with

    state.status=TLS13_DISCONNECTED;
	state.max_record=0;
    state.cipher_suite=0;//TLS_AES_128_GCM_SHA256;              // cipher suite
    initCryptoContext(&state.K_send);                       // Transmission key
    initCryptoContext(&state.K_recv);                       // Reception key

    state.HS={0,TLS_MAX_HASH,state.rms};                    // handshake secret
	state.RMS={0,TLS_MAX_HASH,state.rms};					// Resumption Master secret
	state.STS={0,TLS_MAX_HASH,state.sts};					// Server traffic secret
	state.CTS={0,TLS_MAX_HASH,state.cts};					// Client traffic secret

#ifdef SHALLOW_STACK
    state.IO= {0,TLS_MAX_IO_SIZE,(char *)malloc(TLS_MAX_IO_SIZE)};  // main input/output buffer
#else
	state.IO={0,TLS_MAX_IO_SIZE,state.io};
#endif
    state.ptr=0;
    state.favourite_group=0;							    // default key exchage group
    initTicketContext(&state.T);                            // Resumption ticket - may be added to session state
    return state;
}

// build client's chosen set of extensions, and assert expectations of server responses
// The User may want to change the mix of optional extensions
// mode=0 - full handshake
// mode=1 - resumption handshake
// mode=2 = External PSK handshake
static void buildExtensions(TLS_session *session,octad *EXT,octad *PK,ee_status *expectations,int mode)
{
	int groups[TLS_MAX_SUPPORTED_GROUPS];
	int nsg=SAL_groups(groups);
	int sigAlgs[TLS_MAX_SUPPORTED_SIGS];
	int nsa=SAL_sigs(sigAlgs);
	int sigAlgsCert[TLS_MAX_SUPPORTED_SIGS];
	int nsac=SAL_sigCerts(sigAlgsCert);
    char alpn[20];
    octad ALPN={0,sizeof(alpn),alpn};         // ALPN
    int tlsVersion=TLS1_3;
    int pskMode=PSKWECDHE;
#ifdef TLS_APPLICATION_PROTOCOL
    OCT_append_string(&ALPN,(char *)TLS_APPLICATION_PROTOCOL);
#endif
	if (mode!=0)
	{  // resumption
		nsg=1;
		groups[0]=session->favourite_group; // Only allow the group already agreed
	}
	OCT_kill(EXT);
	addServerNameExt(EXT,session->hostname); expectations->server_name=true;  // Server Name extension - acknowledgement is expected
	addSupportedGroupsExt(EXT,nsg,groups);
	addKeyShareExt(EXT,session->favourite_group,PK); // only sending one public key
#ifdef TLS_APPLICATION_PROTOCOL
	addALPNExt(EXT,&ALPN); expectations->alpn=true; // only supporting one application protocol
#endif
	addPSKModesExt(EXT,pskMode);
	addVersionExt(EXT,tlsVersion);
#ifdef MAX_RECORD
	addRSLExt(EXT,MAX_RECORD);               // demand a fragment size limit
#else
	if (mode!=2)
	{
		addMFLExt(EXT,TLS_MAX_FRAG);  expectations->max_frag_length=true; // ask for max fragment length - server may not agree - but no harm in asking
	}
#endif
	addPadding(EXT,SAL_randomByte()%16);  // add some random padding (because I can)

	if (mode==0) // full handshake
	{ // need signature related extensions for full handshake
		addSigAlgsExt(EXT,nsa,sigAlgs);
		addSigAlgsCertExt(EXT,nsac,sigAlgsCert);
	} 
}

// Exchange Client/Server "Hellos"
static int TLS13_exchange_hellos(TLS_session *session)
{
    ret rtn;
    int i,pskid;
    int kex,hashtype;
	int nsa,nsc,nsg,nsac;
    bool resumption_required=false;

//    int csigAlgs[TLS_MAX_SUPPORTED_SIGS]; // acceptable client cert signature types

	int ciphers[TLS_MAX_CIPHER_SUITES];
	nsc=SAL_ciphers(ciphers);  
	int groups[TLS_MAX_SUPPORTED_GROUPS];
	nsg=SAL_groups(groups);

#ifdef SHALLOW_STACK
    octad CSK = {0, TLS_MAX_KEX_SECRET_KEY_SIZE, (char *)malloc(TLS_MAX_KEX_SECRET_KEY_SIZE)};
    octad CPK = {0, TLS_MAX_KEX_PUB_KEY_SIZE, (char *)malloc(TLS_MAX_KEX_PUB_KEY_SIZE)}; 
    octad SPK = {0, TLS_MAX_KEX_CIPHERTEXT_SIZE, (char *)malloc(TLS_MAX_KEX_CIPHERTEXT_SIZE)};   
#else
    char csk[TLS_MAX_KEX_SECRET_KEY_SIZE];   // clients key exchange secret key
    octad CSK = {0, sizeof(csk), csk};
    char cpk[TLS_MAX_KEX_PUB_KEY_SIZE];      // Client key exchange Public Key (shared memory)
    octad CPK = {0, sizeof(cpk), cpk}; 
    char spk[TLS_MAX_KEX_CIPHERTEXT_SIZE];
    octad SPK = {0, sizeof(spk), spk};       // Server's key exchange Public Key/Ciphertext
#endif
    char ss[TLS_MAX_SHARED_SECRET_SIZE];     // key exchange Shared Secret 
    octad SS = {0, sizeof(ss), ss};    
    char ch[TLS_MAX_HELLO];              // Client Hello
    octad CH = {0, sizeof(ch), ch};
    char ext[TLS_MAX_EXTENSIONS];
    octad EXT={0,sizeof(ext),ext};       // Extensions                  
    char es[TLS_MAX_HASH];               // Early Secret
    octad ES = {0,sizeof(es),es};
    char hh[TLS_MAX_HASH];               
    octad HH={0,sizeof(hh),hh};          // Transcript hashes 
    char cook[TLS_MAX_COOKIE];
    octad COOK={0,sizeof(cook),cook};    // Cookie
    char crn[32];
    octad CRN = {0, sizeof(crn), crn};

    ee_status enc_ext_resp={false,false,false,false};  // encrypted extensions expectations
    ee_status enc_ext_expt={false,false,false,false};  // encrypted extensions responses

    log(IO_PROTOCOL,(char *)"Attempting Full Handshake\n",NULL,0,NULL);

    session->favourite_group=groups[0]; // only sending one key share - so choose first in our list
//
// Generate key pair in favourite group
//
    SAL_generateKeyPair(session->favourite_group,&CSK,&CPK);   
    log(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);
    log(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&CPK);

// Client Hello
    SAL_randomOctad(32,&CRN);

// First build our preferred mix of client Hello extensions, based on our capabililities
	buildExtensions(session,&EXT,&CPK,&enc_ext_expt,0);

// create and send Client Hello octad
    sendClientHello(session,TLS1_0,&CH,&CRN,false,&EXT,0,false,true);  
//
//
//   ----------------------------------------------------------> client Hello
//
//    
    log(IO_DEBUG,(char *)"Client Hello sent\n",NULL,0,NULL);

// Process Server Hello response
    rtn=getServerHello(session,kex,&COOK,&SPK,pskid);
//
//
//  <--------------------------------- server Hello (or helloRetryRequest?)
//
//
    if (badResponse(session,rtn)) 
    {
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
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
        sendAlert(session,ILLEGAL_PARAMETER);
        logCipherSuite(session->cipher_suite);
        log(IO_DEBUG,(char *)"Cipher_suite not valid\n",NULL,0,NULL);
        log(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
    }
    logCipherSuite(session->cipher_suite);
    deriveEarlySecrets(hashtype,NULL,&ES,NULL,NULL);   // Early Secret
    log(IO_DEBUG,(char *)"Early Secret= ",NULL,0,&ES);

// Initialise Transcript Hash
// For Transcript hash we must use cipher-suite hash function
    initTranscriptHash(session);
    if (rtn.val==HANDSHAKE_RETRY)  // Was serverHello an helloRetryRequest?
    {
        log(IO_DEBUG,(char *)"Server HelloRetryRequest= ",NULL,0,&session->IO);
        runningSyntheticHash(session,&CH,&EXT); // RFC 8446 section 4.4.1
        runningHashIOrewind(session);      // Hash of helloRetryRequest

        bool supported=false;
        for (int i=0;i<nsg;i++)
            if (kex==groups[i]) supported=true; 

        if (!supported || kex==session->favourite_group)  // kex is alternate group suggested by server
        { // its not supported or its the same one I originally chose !?
            sendAlert(session,ILLEGAL_PARAMETER);
            log(IO_DEBUG,(char *)"Group not supported, or no change as result of HRR\n",NULL,0,NULL);   
            log(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
            return TLS_FAILURE;
        }

// Repair clientHello by supplying public key of Server's preferred key exchange algorithm
// build new client Hello extensions

// generate new key pair in new server selected group 
        session->favourite_group=kex;  // OK, lets try the alternate
        SAL_generateKeyPair(session->favourite_group,&CSK,&CPK); 
		buildExtensions(session,&EXT,&CPK,&enc_ext_expt,0);

        if (COOK.len!=0)
            addCookieExt(&EXT,&COOK);   // there was a cookie in the HRR ... so send it back in an extension
        sendCCCS(session);  // send Client Cipher Change

// create and send new Client Hello octad
        sendClientHello(session,TLS1_2,&CH,&CRN,false,&EXT,0,true,true);
//
//
//  ---------------------------------------------------> Resend Client Hello
//
//
        log(IO_DEBUG,(char *)"Client Hello re-sent\n",NULL,0,NULL);

        int skex; // Server Key Exchange Group - should be same as kex
        rtn=getServerHello(session,skex,&COOK,&SPK,pskid);
        
        if (badResponse(session,rtn)) 
        {
#ifdef SHALLOW_STACK
			free(CSK.val); free(CPK.val); free(SPK.val);
#endif
            return TLS_FAILURE;
        }

        if (rtn.val==HANDSHAKE_RETRY)
        { // only one retry allowed
            log(IO_DEBUG,(char *)"A second Handshake Retry Request?\n",NULL,0,NULL); 
            sendAlert(session,UNEXPECTED_MESSAGE);
            log(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
            return TLS_FAILURE;
        }

        if (kex!=skex)
        {
            log(IO_DEBUG,(char *)"Server came back with wrong group\n",NULL,0,NULL); 
            sendAlert(session,ILLEGAL_PARAMETER);
            log(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
            return TLS_FAILURE;
        }
//
//
//  <---------------------------------------------------------- server Hello
//
//


        resumption_required=true;
    }
    log(IO_DEBUG,(char *)"Server Hello= ",NULL,0,&session->IO); 
    logServerHello(session->cipher_suite,pskid,&SPK,&COOK);
    logKeyExchange(kex);
// Hash Transcript the Hellos 
    runningHash(session,&CH);
    runningHash(session,&EXT);
    runningHashIOrewind(session);
    transcriptHash(session,&HH);        // HH = hash of clientHello+serverHello

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    bool nonzero=SAL_generateSharedSecret(kex,&CSK,&SPK,&SS);
	if (!nonzero)
	{ // all zero shared secret??
        sendAlert(session,ILLEGAL_PARAMETER);
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
	}
    log(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);

// Extract Handshake secret, Client and Server Handshake Traffic secrets, Client and Server Handshake keys and IVs from Transcript Hash and Shared secret

    deriveHandshakeSecrets(session,&SS,&ES,&HH);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    log(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&session->HS);
    log(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    log(IO_DEBUG,(char *)"Client handshake key= ",NULL,0,&(session->K_send.K));
    log(IO_DEBUG,(char *)"Client handshake iv= ",NULL,0,&(session->K_send.IV));
    log(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&session->STS);
    log(IO_DEBUG,(char *)"Server handshake key= ",NULL,0,&(session->K_recv.K));
    log(IO_DEBUG,(char *)"Server handshake iv= ",NULL,0,&(session->K_recv.IV));
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
// 1. get encrypted extensions
    rtn=getServerEncryptedExtensions(session,&enc_ext_expt,&enc_ext_resp);   
//
//
//  <------------------------------------------------- {Encrypted Extensions}
//
//
    if (badResponse(session,rtn)) 
        return TLS_FAILURE;
    
    logEncExt(&enc_ext_expt,&enc_ext_resp);
    log(IO_DEBUG,(char *)"Encrypted Extensions Processed\n",NULL,0,NULL);
    if (resumption_required) return TLS_RESUMPTION_REQUIRED;
    return TLS_SUCCESS;
}

// check that the server is trusted
static int TLS13_server_trust(TLS_session *session)
{
    ret rtn;
    int kex,hashtype;
	int nsa,nsc,nsg,nsac;
    bool ccs_sent=false;

#ifdef SHALLOW_STACK
    octad SERVER_PK = {0,TLS_MAX_SIG_PUB_KEY_SIZE,(char *)malloc(TLS_MAX_SIG_PUB_KEY_SIZE)};  // Server's cert sig public key
    octad SCVSIG={0,TLS_MAX_SIGNATURE_SIZE,(char *)malloc(TLS_MAX_SIGNATURE_SIZE)};           // Server's digital signature on transcript
#else
    char server_pk[TLS_MAX_SIG_PUB_KEY_SIZE];
    octad SERVER_PK = {0,sizeof(server_pk),server_pk}; // Server's cert sig public key
    char scvsig[TLS_MAX_SIGNATURE_SIZE];
    octad SCVSIG={0,sizeof(scvsig),scvsig};           // Server's digital signature on transcript
#endif
    char hh[TLS_MAX_HASH];               
    octad HH={0,sizeof(hh),hh};          // Transcript hashes
    char fh[TLS_MAX_HASH];
    octad FH={0,sizeof(fh),fh};       

    char fin[TLS_MAX_HASH];
    octad FIN={0,sizeof(fin),fin};                    // Server's finish message

    hashtype=SAL_hashType(session->cipher_suite);

// Client now receives certificate chain and verifier from Server. Need to parse these out, check CA signature on the cert
// (maybe its self-signed), extract public key from cert, and use this public key to check server's signature 
// on the "verifier". Note Certificate signature might use old methods, but server will use PSS padding for its signature (or ECC).
    rtn=getCheckServerCertificateChain(session,&SERVER_PK,&SCVSIG);  // note SCVSIG is used here as workspace
//
//
//  <---------------------------------------------------------- {Certificate}
//
//
    if (badResponse(session,rtn))
    {    
#ifdef SHALLOW_STACK
        free(SERVER_PK.val); free (SCVSIG.val);
#endif
        return TLS_FAILURE;
    }
    transcriptHash(session,&HH); // HH = hash of clientHello+serverHello+encryptedExtensions+CertChain
    log(IO_DEBUG,(char *)"Certificate Chain is valid\n",NULL,0,NULL);
    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+CT) = ",NULL,0,&HH); 

// 3. get verifier signature
    int sigalg;
    rtn=getServerCertVerify(session,&SCVSIG,sigalg);
//
//
//  <---------------------------------------------------- {Certificate Verify}
//
//
    if (badResponse(session,rtn)) 
    {
#ifdef SHALLOW_STACK
        free(SERVER_PK.val); free (SCVSIG.val);
#endif
        return TLS_FAILURE;
    }
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify
    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV) = ",NULL,0,&FH);
    log(IO_DEBUG,(char *)"Server Transcript Signature= ",NULL,0,&SCVSIG);

    logSigAlg(sigalg);
    if (!checkServerCertVerifier(sigalg,&SCVSIG,&HH,&SERVER_PK))
    {
        sendAlert(session,DECRYPT_ERROR);
        log(IO_DEBUG,(char *)"Server Cert Verification failed\n",NULL,0,NULL);
        log(IO_PROTOCOL,(char *)"Full Handshake failed\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
        free(SERVER_PK.val); free (SCVSIG.val);
#endif
        return TLS_FAILURE;
    }
    log(IO_DEBUG,(char *)"Server Cert Verification OK\n",NULL,0,NULL);
#ifdef SHALLOW_STACK
    free(SERVER_PK.val); free (SCVSIG.val);
#endif
// 4. get Server Finished
    rtn=getServerFinished(session,&FIN);
//
//
//  <------------------------------------------------------ {Server Finished}
//
//

    if (badResponse(session,rtn))
        return TLS_FAILURE;
    
    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendAlert(session,DECRYPT_ERROR);
        log(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        log(IO_DEBUG,(char *)"Full Handshake failed\n",NULL,0,NULL);
        return TLS_FAILURE;
    }
    log(IO_DEBUG,(char *)"\nServer Data is verified\n",NULL,0,NULL);

    return TLS_SUCCESS;
}

// client supplies trust to server, given servers list of acceptable signature types
static void TLS13_client_trust(TLS_session *session,int nsa,int *sa)
{
    int hashtype;
	int nsc,nsg,nsac;

#ifdef SHALLOW_STACK
    octad CLIENT_KEY={0,TLS_MAX_SIG_SECRET_KEY_SIZE,(char *)malloc(TLS_MAX_SIG_SECRET_KEY_SIZE)};   // Client secret key
    octad CLIENT_CERTCHAIN={0,TLS_MAX_CLIENT_CHAIN_SIZE,(char *)malloc(TLS_MAX_CLIENT_CHAIN_SIZE)};   // Client certificate chain
    octad CCVSIG={0,TLS_MAX_SIGNATURE_SIZE,(char *)malloc(TLS_MAX_SIGNATURE_SIZE)}; 
#else 
    char client_key[TLS_MAX_SIG_SECRET_KEY_SIZE];           
    octad CLIENT_KEY={0,sizeof(client_key),client_key};   // Client secret key
    char client_certchain[TLS_MAX_CLIENT_CHAIN_SIZE];           
    octad CLIENT_CERTCHAIN={0,sizeof(client_certchain),client_certchain};   // Client certificate chain
    char ccvsig[TLS_MAX_SIGNATURE_SIZE];
    octad CCVSIG={0,sizeof(ccvsig),ccvsig};           // Client's digital signature on transcript
#endif
    char th[TLS_MAX_HASH];
    octad TH={0,sizeof(th),th};  // Transcript hash

    int kind=getClientPrivateKeyandCertChain(nsa,sa,&CLIENT_KEY,&CLIENT_CERTCHAIN);
    if (kind!=0)
    { // Yes, I can do that kind of signature
        log(IO_PROTOCOL,(char *)"Client is authenticating\n",NULL,0,NULL);
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
    } else { // No, I can't - send a null cert, and no verifier
        sendClientCertificateChain(session,NULL);
    }
#ifdef SHALLOW_STACK
    free(CLIENT_KEY.val); free(CLIENT_CERTCHAIN.val); free(CCVSIG.val);
#endif
}

// TLS1.3 full handshake - connect to server
static int TLS13_full(TLS_session *session)
{
    ret rtn;
    int kex,hashtype;
	int nsa,nsc,nsg,nsac;
    bool resumption_required=false;
    bool gotacertrequest=false;
    int nccsalgs=0;  // number of client certificate signature algorithms
    int csigAlgs[TLS_MAX_SUPPORTED_SIGS]; // acceptable client cert signature types

    char hh[TLS_MAX_HASH];               
    octad HH={0,sizeof(hh),hh};          // Transcript hashes  
    char th[TLS_MAX_HASH];
    octad TH={0,sizeof(th),th};  
    char chf[TLS_MAX_HASH];                           
    octad CHF={0,sizeof(chf),chf};                    // client verify

    int rval=TLS13_exchange_hellos(session);
    if (rval==TLS_FAILURE)
    {
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    if (rval==TLS_RESUMPTION_REQUIRED)
        resumption_required=true;
        
// 2. get certificate request (maybe..) and certificate chain, check it, get Server public key

    hashtype=SAL_hashType(session->cipher_suite);
    rtn=seeWhatsNext(session);  // get next message type
    if (badResponse(session,rtn)) 
    {
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
            TLS13_clean(session);
            return TLS_FAILURE;
        }
        log(IO_PROTOCOL,(char *)"Certificate Request received\n",NULL,0,NULL);
    }

    rval=TLS13_server_trust(session);
    if (rval==TLS_FAILURE)
    {
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    sendCCCS(session);  // send Client Cipher Change
    transcriptHash(session,&HH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish

    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF) YYY = ",NULL,0,&HH);

// Now its the clients turn to respond
// Send Certificate (if it was asked for, and if I have one) & Certificate Verify.
    OCT_kill(&session->IO);
    session->ptr=0;

    if (gotacertrequest)
    {
#if CLIENT_CERT != NOCERT
        TLS13_client_trust(session,nccsalgs,csigAlgs);
#else
        sendClientCertificateChain(session,NULL);
#endif
    } 
    transcriptHash(session,&TH);

// HH is server finished hash
// TH is client finished hash
// both are needed

    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV])  XXXX = ",NULL,0,&TH);

// create client verify data
// .... and send it to Server
    deriveVeriferData(hashtype,&CHF,&session->CTS,&TH);  
    sendClientFinish(session,&CHF);  
//
//
//  {client Finished} ----------------------------------------------------->
//
//
    log(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 
    transcriptHash(session,&TH); // hash of clientHello+serverHello+encryptedExtensions+CertChain+serverCertVerify+serverFinish(+clientCertChain+clientCertVerify)+clientFinish
    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SCT+SCV+SF+[CCT+CSV]+CF) = ",NULL,0,&TH);

// calculate traffic and application keys from handshake secret and transcript hashes
    deriveApplicationSecrets(session,&HH,&TH,NULL);

    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    log(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    log(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&session->STS);
    log(IO_PROTOCOL,(char *)"FULL Handshake succeeded\n",NULL,0,NULL);
    if (resumption_required) log(IO_PROTOCOL,(char *)"... after handshake resumption\n",NULL,0,NULL);

    OCT_kill(&session->IO);  // clean up IO buffer

    if (resumption_required) return TLS_RESUMPTION_REQUIRED;
    return TLS_SUCCESS;
}

// TLS1.3 fast resumption handshake (0RTT and 1RTT)
// EARLY - First message from Client to Server (should ideally be sent as early data!)
static int TLS13_resume(TLS_session *session,octad *EARLY)
{
    int hashtype,kex,pskid,nsc,nsa,nsg,nsac;
    ret rtn;

#ifdef SHALLOW_STACK
    octad CSK = {0, TLS_MAX_KEX_SECRET_KEY_SIZE, (char *)malloc(TLS_MAX_KEX_SECRET_KEY_SIZE)};
    octad CPK = {0, TLS_MAX_KEX_PUB_KEY_SIZE, (char *)malloc(TLS_MAX_KEX_PUB_KEY_SIZE)}; 
    octad SPK = {0, TLS_MAX_KEX_CIPHERTEXT_SIZE, (char *)malloc(TLS_MAX_KEX_CIPHERTEXT_SIZE)};   
#else
    char csk[TLS_MAX_KEX_SECRET_KEY_SIZE];   
    octad CSK = {0, sizeof(csk), csk};   // clients key exchange secret key
    char cpk[TLS_MAX_KEX_PUB_KEY_SIZE];
    octad CPK = {0, sizeof(cpk), cpk};   // Client's key exchange Public Key
    char spk[TLS_MAX_KEX_CIPHERTEXT_SIZE];
    octad SPK = {0, sizeof(spk), spk};   // Server's key exchange Public Key/Ciphertext
#endif
    char es[TLS_MAX_HASH];               // Early Secret
    octad ES = {0,sizeof(es),es};
    char ss[TLS_MAX_SHARED_SECRET_SIZE];
    octad SS = {0, sizeof(ss), ss};      // Shared Secret

    char ch[TLS_MAX_HELLO];    // Client Hello
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
    char cook[TLS_MAX_COOKIE];
    octad COOK={0,sizeof(cook),cook};   // Cookie
    char bnd[TLS_MAX_HASH];
    octad BND={0,sizeof(bnd),bnd};
    //char bl[TLS_MAX_HASH+3];
    //octad BL={0,sizeof(bl),bl};
    char psk[TLS_MAX_HASH];
    octad PSK={0,sizeof(psk),psk};      // Pre-shared key
    char bk[TLS_MAX_HASH];
    octad BK={0,sizeof(bk),bk};         // Binder key
    char crn[32];
    octad CRN = {0, sizeof(crn), crn};

    unsign32 time_ticket_received,time_ticket_used;
    int origin,lifetime=0;
    unsign32 age,age_obfuscator=0;
    unsign32 max_early_data=0;
#ifdef TRY_EARLY_DATA
    bool have_early_data=true;       // Hope to send client message as early data
#else
    bool have_early_data=false;
#endif
    bool external_psk=false;
    ee_status enc_ext_resp={false,false,false,false};  // encrypted extensions responses 
    ee_status enc_ext_expt={false,false,false,false};  // encrypted extensions expectations

// Extract Ticket parameters
    lifetime=session->T.lifetime;
    age_obfuscator=session->T.age_obfuscator;
    max_early_data=session->T.max_early_data;
    OCT_copy(&PSK,&session->T.PSK);
    time_ticket_received=session->T.birth;
    session->cipher_suite=session->T.cipher_suite;
    session->favourite_group=session->T.favourite_group;
    origin=session->T.origin;

    log(IO_PROTOCOL,(char *)"Attempting Resumption Handshake\n",NULL,0,NULL);
    logTicket(&session->T); // lifetime,age_obfuscator,max_early_data,&NONCE,&ETICK);

    if (max_early_data==0 || EARLY==NULL)
        have_early_data=false;      // early data not allowed - or I don't have any

// Generate Early secret and Binder Key from PSK

    hashtype=SAL_hashType(session->cipher_suite);
    initTranscriptHash(session);

    if (origin==TLS_EXTERNAL_PSK)
    { // its an external PSK
        external_psk=true;
        deriveEarlySecrets(hashtype,&PSK,&ES,&BK,NULL);
    } else {
        external_psk=false;
        deriveEarlySecrets(hashtype,&PSK,&ES,NULL,&BK);   // compute early secret and Binder Key from PSK
    }
    //log(IO_DEBUG,(char *)"PSK= ",NULL,0,&PSK); 
    log(IO_DEBUG,(char *)"Binder Key= ",NULL,0,&BK); 
    log(IO_DEBUG,(char *)"Early Secret= ",NULL,0,&ES);

// Generate key pair in favourite group - use same favourite group that worked before for this server - so should be no HRR
    SAL_generateKeyPair(session->favourite_group,&CSK,&CPK);
    log(IO_DEBUG,(char *)"Private key= ",NULL,0,&CSK);  
    log(IO_DEBUG,(char *)"Client Public key= ",NULL,0,&CPK);  

// Client Hello
    SAL_randomOctad(32,&CRN);
// First build standard client Hello extensions

	int resmode=1;
	if (origin==TLS_EXTERNAL_PSK)
		resmode=2;
	buildExtensions(session,&EXT,&CPK,&enc_ext_expt,resmode);	
	
    if (have_early_data)
    {
        addEarlyDataExt(&EXT); enc_ext_expt.early_data=true;   // try sending client message as early data if allowed
    }
    age=0;
    if (!external_psk)
    { // Its NOT an external pre-shared key
        time_ticket_used=(unsign32)millis();
        age=time_ticket_used-time_ticket_received; // age of ticket in milliseconds - problem for some sites which work for age=0 ??
//printf("Ticket age= %d\n",age);
//age+=500;
        log(IO_DEBUG,(char *)"Ticket age= ",(char *)"%x",age,NULL);
        age+=age_obfuscator;
        log(IO_DEBUG,(char *)"obfuscated age = ",(char *)"%x",age,NULL);
    }

    int extra=addPreSharedKeyExt(&EXT,age,&session->T.TICK,SAL_hashLen(hashtype)); // must be last extension..

// create and send Client Hello octad
    sendClientHello(session,TLS1_2,&CH,&CRN,true,&EXT,extra,false,false);  // don't transmit yet - wait for binders
//
//
//   ----------------------------------------------------------> client Hello
//
//
    runningHash(session,&CH); 
    runningHash(session,&EXT);
    transcriptHash(session,&HH);            // HH = hash of Truncated clientHello
    log(IO_DEBUG,(char *)"Hash of Truncated client Hello",NULL,0,&HH);
    deriveVeriferData(hashtype,&BND,&BK,&HH);
    sendBinder(session,&BND,true);               // Send Binders
    log(IO_DEBUG,(char *)"Client Hello + Binder sent\n",NULL,0,NULL);
    log(IO_DEBUG,(char *)"Binder= ",NULL,0,&BND);
  
    transcriptHash(session,&HH);            // HH = hash of full clientHello
    log(IO_DEBUG,(char *)"Hash of Completed client Hello",NULL,0,&HH);

    if (have_early_data)
        sendCCCS(session);

    deriveLaterSecrets(hashtype,&ES,&HH,&CETS,NULL);   // Get Client Early Traffic Secret from transcript hash and ES
    log(IO_DEBUG,(char *)"Client Early Traffic Secret= ",NULL,0,&CETS); 
    createSendCryptoContext(session,&CETS);
// if its allowed, send client message as (encrypted!) early data
    if (have_early_data)
    {
        log(IO_APPLICATION,(char *)"Sending some early data\n",NULL,0,NULL);
        sendClientMessage(session,APPLICATION,TLS1_2,EARLY,NULL,true);
//
//
//   ----------------------------------------------------------> (Early Data)
//
//
    } 

// Process Server Hello
    rtn=getServerHello(session,kex,&COOK,&SPK,pskid);
    if (badResponse(session,rtn)) 
    {
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
    }
//
//
//  <---------------------------------------------------------- server Hello
//
//
    //runningHash(session,&session->IO); // Hashing Server Hello
    runningHashIOrewind(session); // Hashing Server Hello
    transcriptHash(session,&HH);       // HH = hash of clientHello+serverHello

    if (pskid<0)
    { // Ticket rejected by Server (as out of date??)
        log(IO_PROTOCOL,(char *)"Ticket rejected by server\n",NULL,0,NULL);
        log(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE; 
    }

	if (pskid>0)
	{ // pskid out-of-range (only one allowed)
        sendAlert(session,ILLEGAL_PARAMETER);
        log(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
	}

    logServerHello(session->cipher_suite,pskid,&SPK,&COOK);
    logKeyExchange(kex);

    if (rtn.val==HANDSHAKE_RETRY || kex!=session->favourite_group)
    { // should not happen
        sendAlert(session,UNEXPECTED_MESSAGE);
        log(IO_DEBUG,(char *)"No change possible as result of HRR\n",NULL,0,NULL); 
        log(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
    }
    log(IO_DEBUG,(char *)"serverHello= ",NULL,0,&session->IO); 

// Generate Shared secret SS from Client Secret Key and Server's Public Key
    bool nonzero=SAL_generateSharedSecret(kex,&CSK,&SPK,&SS);
	if (!nonzero)
	{ // all zero shared secret??
        sendAlert(session,ILLEGAL_PARAMETER);
        TLS13_clean(session);
#ifdef SHALLOW_STACK
        free(CSK.val); free(CPK.val); free(SPK.val);
#endif
        return TLS_FAILURE;
	}
    log(IO_DEBUG,(char *)"Shared Secret= ",NULL,0,&SS);


    deriveHandshakeSecrets(session,&SS,&ES,&HH); 
    createRecvCryptoContext(session,&session->STS);

    log(IO_DEBUG,(char *)"Handshake Secret= ",NULL,0,&session->HS);
    log(IO_DEBUG,(char *)"Client handshake traffic secret= ",NULL,0,&session->CTS);
    log(IO_DEBUG,(char *)"Server handshake traffic secret= ",NULL,0,&session->STS);

#ifdef SHALLOW_STACK
    free(CSK.val); free(CPK.val); free(SPK.val);
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
        TLS13_clean(session);
        return TLS_FAILURE;
    }
    logEncExt(&enc_ext_expt,&enc_ext_resp);
    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension
    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE) = ",NULL,0,&FH); 

// 2. get server finish
    rtn=getServerFinished(session,&FIN);   // Finished
//
//
//  <------------------------------------------------------ {Server Finished}
//
//
    if (badResponse(session,rtn)) 
    {
        TLS13_clean(session);
        return TLS_FAILURE;
    }

// Now indicate End of Early Data, encrypted with 0-RTT keys
    transcriptHash(session,&HH); // hash of clientHello+serverHello+encryptedExtension+serverFinish
    if (enc_ext_resp.early_data)
    {
        sendEndOfEarlyData(session);     // Should only be sent if server has accepted Early data - see encrypted extensions!
        log(IO_DEBUG,(char *)"Send End of Early Data \n",NULL,0,NULL);
    }
    transcriptHash(session,&TH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData
    log(IO_DEBUG,(char *)"Transcript Hash (CH+SH+EE+SF+ED) = ",NULL,0,&TH); 

// Switch to handshake keys
    createSendCryptoContext(session,&session->CTS);
    if (!checkVeriferData(hashtype,&FIN,&session->STS,&FH))
    {
        sendAlert(session,DECRYPT_ERROR);
        log(IO_DEBUG,(char *)"Server Data is NOT verified\n",NULL,0,NULL);
        log(IO_PROTOCOL,(char *)"Resumption Handshake failed\n",NULL,0,NULL);
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
    log(IO_DEBUG,(char *)"Server Data is verified\n",NULL,0,NULL);
    log(IO_DEBUG,(char *)"Client Verify Data= ",NULL,0,&CHF); 

    transcriptHash(session,&FH); // hash of clientHello+serverHello+encryptedExtension+serverFinish+EndOfEarlyData+clientFinish

// calculate traffic and application keys from handshake secret and transcript hashes, and store in session
    deriveApplicationSecrets(session,&HH,&FH,NULL);  
    createSendCryptoContext(session,&session->CTS);
    createRecvCryptoContext(session,&session->STS);

    log(IO_DEBUG,(char *)"Client application traffic secret= ",NULL,0,&session->CTS);
    log(IO_DEBUG,(char *)"Server application traffic secret= ",NULL,0,&session->STS);
    log(IO_PROTOCOL,(char *)"RESUMPTION Handshake succeeded\n",NULL,0,NULL);

    OCT_kill(&session->IO);  // clean up IO buffer

    if (enc_ext_resp.early_data)
    {
        log(IO_PROTOCOL,(char *)"Application Message accepted as Early Data\n\n",EARLY->val,0,NULL);
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
	session->status=TLS13_HANDSHAKING;
    if (ticket_still_good(&session->T))
    { // have a good ticket? Try it.
        rtn=TLS13_resume(session,EARLY);
        if (rtn==TLS_EARLY_DATA_ACCEPTED) early_went=true;
    } else {
        log(IO_PROTOCOL,(char *)"Resumption Ticket not found or invalid\n",NULL,0,NULL);
        rtn=TLS13_full(session);
    }
    initTicketContext(&session->T); // clear out any ticket
    
    if (rtn==0)  // failed to connect
	{
		//session->status=TLS13_DISCONNECTED;
        return false;
	}
    
    if (!early_went && EARLY!=NULL)
        TLS13_send(session,EARLY);  // didn't go early, so send it now
    session->status=TLS13_CONNECTED;
    return true;   // exiting with live session, ready to receive fresh ticket
}

// send a message post-handshake
void TLS13_send(TLS_session *state,octad *GET)
{
    log(IO_APPLICATION,(char *)"Sending Application Message\n\n",GET->val,0,NULL);
    sendClientMessage(state,APPLICATION,TLS1_2,GET,NULL,true);
}

// Process Server records received post-handshake
// Should be mostly application data, but..
// could be more handshake data disguised as application data
// For example could include a ticket. Also receiving key K_recv might be updated.

int TLS13_recv(TLS_session *session,octad *REC)
{
    ret r;
    int nce,nb,len,te,type,nticks,kur,rtn;//,ptr=0;
    bool fin=false;
    //bool gotaticket=false;
    unsign32 time_ticket_received;
    octad TICK;  // Ticket raw data
    TICK.len=0;
    session->ptr=0;
    nticks=0; // number of tickets received
	bool PENDING_KEY_UPDATE=false;
    while (1)
    {
        log(IO_PROTOCOL,(char *)"Waiting for Server input \n",NULL,0,NULL);
        OCT_kill(&session->IO); session->ptr=0;
        type=getServerRecord(session);  // get first fragment to determine type
        if (type<0)
		{
			sendAlert(session,alert_from_cause(type));
            return type;   // its an error
		}
        if (type==TIMED_OUT)
        {
            log(IO_PROTOCOL,(char *)"TIME_OUT\n",NULL,0,NULL);
            return TIMED_OUT;
        }
        if (type==HSHAKE)
        {
            while (1)
            {
                r=parseIntorPull(session,1); nb=r.val; if (r.err) break;
                r=parseIntorPull(session,3); len=r.val; if (r.err) break;   // message length
                switch (nb)
                {
                case TICKET :   // keep last ticket
                   /* if (gotaticket)
                    {
                        session->ptr+=len;

                        if (session->ptr==session->IO.len)
                            fin=true; // record finished
                        if (fin) break;
                            continue;
                    } */
                    r=parseoctadorPullptrX(session,&TICK,len);    // just copy out pointer to this
                    nticks++;
                    rtn=parseTicket(&TICK,(unsign32)millis(),&session->T);       // extract into ticket structure T, and keep for later use  
                    if (rtn==BAD_TICKET) {
                        session->T.valid=false;
                        log(IO_PROTOCOL,(char *)"Got a bad ticket ",NULL,0,NULL);
                    } else {
                        session->T.cipher_suite=session->cipher_suite;
                        session->T.favourite_group=session->favourite_group;
                        session->T.valid=true;
                        log(IO_PROTOCOL,(char *)"Got a ticket with lifetime (minutes)= ",(char *)"%d",session->T.lifetime/60,NULL);
                    }

                    if (session->ptr==session->IO.len)
                    {
                        fin=true; // record finished
                        //OCT_shift_left(&session->IO,session->ptr); // rewind IO buffer
                    }
                    //gotaticket=true;
                    if (fin) break;
                    continue;

               case KEY_UPDATE :
                    if (len!=1)
                    {
                        log(IO_PROTOCOL,(char *)"Something wrong\n",NULL,0,NULL);
						sendAlert(session,DECODE_ERROR);
                        return BAD_RECORD;
                    }
                    r=parseIntorPull(session,1); kur=r.val; if (r.err) break;
                    if (kur==TLS13_UPDATE_NOT_REQUESTED)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);  // reset record number
                        log(IO_PROTOCOL,(char *)"RECEIVING KEYS UPDATED\n",NULL,0,NULL);
                    }
                    if (kur==TLS13_UPDATE_REQUESTED)
                    {
                        deriveUpdatedKeys(&session->K_recv,&session->STS);
						PENDING_KEY_UPDATE=true;
                        log(IO_PROTOCOL,(char *)"Key update notified - client should do the same\n",NULL,0,NULL);
                        log(IO_PROTOCOL,(char *)"RECEIVING KEYS UPDATED\n",NULL,0,NULL);
                    }
					if (kur!=TLS13_UPDATE_NOT_REQUESTED && kur!=TLS13_UPDATE_REQUESTED)
					{
                        log(IO_PROTOCOL,(char *)"Bad Request Update value\n",NULL,0,NULL);
                        sendAlert(session,ILLEGAL_PARAMETER);
                        return BAD_REQUEST_UPDATE;
					}
                    if (session->ptr==session->IO.len) fin=true; // record finished
                    if (fin) break;
                    continue;

                default:
                    log(IO_PROTOCOL,(char *)"Unsupported Handshake message type ",(char *)"%x",nb,NULL);
                    fin=true;
                    break;            
                }
                if (r.err || fin) break;
            }
			if (r.err) {
				sendAlert(session,alert_from_cause(r.err));
				break;
			}
        }
		if (PENDING_KEY_UPDATE)
		{
			sendKeyUpdate(session,TLS13_UPDATE_NOT_REQUESTED); // tell server to update their receiving keys
			log(IO_PROTOCOL,(char *)"SENDING KEYS UPDATED\n",NULL,0,NULL);
            PENDING_KEY_UPDATE=false;
		}
        if (type==APPLICATION)
        { // application data received - return it
            OCT_copy(REC,&session->IO);
            break;
        }
        if (type==ALERT)
        {
            log(IO_PROTOCOL,(char *)"*** Alert received - ",NULL,0,NULL);
            logAlert(session->IO.val[1]);
            if (session->IO.val[1]==CLOSE_NOTIFY)
                return CLOSURE_ALERT_RECEIVED;
		    else
                return ERROR_ALERT_RECEIVED;    // Alert received
        }
    }

    if (session->T.valid)
    { // if ticket received, recover PSK
        recoverPSK(session); // recover PSK using NONCE and RMS, and store it with ticket
//printf("2. PSK.len= %d\n",session->T.PSK.len);
        session->T.origin=TLS_FULL_HANDSHAKE;
    } else {
        log(IO_PROTOCOL,(char *)"No ticket provided \n",NULL,0,NULL);
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
    OCT_kill(&session->HS);
    initCryptoContext(&session->K_send);
    initCryptoContext(&session->K_recv);
    session->status=TLS13_DISCONNECTED;
}

void TLS13_stop(TLS_session *session)
{
    sendAlert(session,CLOSE_NOTIFY);
}

void TLS13_end(TLS_session *session)
{	
    TLS13_clean(session);
    endTicketContext(&session->T);
#ifdef SHALLOW_STACK
    free(session->IO.val);
#endif
}
