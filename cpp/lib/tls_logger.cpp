// 
// Log protocol progress
//
#include "tls_logger.h"

#ifdef TLS_ARDUINO
#include <Arduino.h>
#else
#include <stdio.h>
#endif

// all terminal output redirected here
void myprintf(char *s)
{
#ifdef TLS_ARDUINO
    Serial.print(s);
#else
    printf("%s",s);
#endif
}

// log debug string and info or octad
// if string is not NULL, output info, with format in string
// if O is not null, output octad in hex.

void log(int logit,char *preamble,char *string,unsign32 info,octad *O)
{
    if (logit>VERBOSITY) return;

#if VERBOSITY>IO_NONE    
    char w[16];
    myprintf(preamble);

    if (O!=NULL)
    {
        char buff[LOG_OUTPUT_TRUNCATION+8];
        bool res=OCT_output_hex(O,LOG_OUTPUT_TRUNCATION,buff);
        sprintf(w,"(%d) ",O->len);
        myprintf(w);
        myprintf(buff);
        if (!res) myprintf((char *)" (truncated)");
        myprintf((char *)"\n");
        return;
    }    

    if (string!=NULL)
    { // if its bigger than 6 its not a format descriptor ???
        if (strlen(string)>6)
            myprintf(string);
        else
        {
            sprintf(w,string,info);
            myprintf(w);
        }
        myprintf((char *)"\n");
        return;
    }
 
#endif
}

static void nameCipherSuite(int cipher_suite)
{
    switch (cipher_suite)
    {
    case TLS_AES_128_GCM_SHA256:
        myprintf((char *)"TLS_AES_128_GCM_SHA256\n");
        break;
    case TLS_AES_256_GCM_SHA384:
        myprintf((char *)"TLS_AES_256_GCM_SHA384\n");   
        break;
    case TLS_CHACHA20_POLY1305_SHA256:
        myprintf((char *)"TLS_CHACHA20_POLY1305_SHA256\n");   
        break;
    default:
        myprintf((char *)"Non-standard\n");   
        break;
    }
}

void logCipherSuite(int cipher_suite)
{
#if VERBOSITY >= IO_DEBUG
    log(IO_DEBUG,(char *)"Cipher Suite is ",NULL,0,NULL);
    nameCipherSuite(cipher_suite);
#endif
}

static void nameKeyExchange(int kex)
{
#if VERBOSITY >= IO_PROTOCOL
    switch (kex)
    {
    case X25519:
        myprintf((char *)"X25519\n");
        break;
    case SECP256R1:
        myprintf((char *)"SECP256R1\n");   
        break;
    case SECP384R1:
        myprintf((char *)"SECP384R1\n");   
        break;
    case MLKEM768:
        myprintf((char *)"MLKEM768\n");
        break;
    case HYBRID_KX:
        myprintf((char *)"MLKEM768 + X25519\n");
        break;
    default:
        myprintf((char *)"Non-standard\n");   
        break;
    }
#endif
}

void logKeyExchange(int kex)
{
    log(IO_PROTOCOL,(char *)"Key Exchange Group is ",NULL,0,NULL);
    nameKeyExchange(kex);
}

static void nameSigAlg(int sigAlg)
{
#if VERBOSITY >= IO_PROTOCOL
    switch (sigAlg)
    {
    case ECDSA_SECP256R1_SHA256:
        myprintf((char *)"ECDSA_SECP256R1_SHA256\n");
        break;
    case RSA_PSS_RSAE_SHA256:
        myprintf((char *)"RSA_PSS_RSAE_SHA256\n");   
        break;
    case RSA_PKCS1_SHA256:
        myprintf((char *)"RSA_PKCS1_SHA256\n");   
        break;
    case ECDSA_SECP384R1_SHA384:
        myprintf((char *)"ECDSA_SECP384R1_SHA384\n");
        break;
    case RSA_PSS_RSAE_SHA384:
        myprintf((char *)"RSA_PSS_RSAE_SHA384\n");   
        break;
    case RSA_PKCS1_SHA384:
        myprintf((char *)"RSA_PKCS1_SHA384\n");   
        break;
    case RSA_PSS_RSAE_SHA512:
        myprintf((char *)"RSA_PSS_RSAE_SHA512\n");   
        break;
    case RSA_PKCS1_SHA512:
        myprintf((char *)"RSA_PKCS1_SHA512\n");   
        break;
    case ED25519:
        myprintf((char *)"ED25519\n");   
        break;
    case MLDSA44:
        myprintf((char *)"MLDSA44\n");   
        break;
    case MLDSA65:
        myprintf((char *)"MLDSA65\n");   
        break;
    case MLDSA44_P256:
        myprintf((char *)"MLDSA44 + P256\n");   
        break;
#ifdef SQISIGN_TEST
    case SQISIGN3:
        myprintf((char *)"SQISIGN3\n");
        break;
    case SQISIGN3_ED448:
        myprintf((char *)"SQISIGN3 + ED448\n");
        break;
#endif
    default:
        myprintf((char *)"Non-standard\n");   
        break;
    }
#endif
}

void logSigAlg(int sigAlg)
{
    log(IO_PROTOCOL,(char *)"Transcript Signature Algorithm is ",NULL,0,NULL);
    nameSigAlg(sigAlg);
}

// log Encrypted Extensions Responses
void logEncExt(ee_status *expected,ee_status *received)
{
#if VERBOSITY >= IO_PROTOCOL
    if (expected->early_data)
    {
        if (received->early_data)
        {
            log(IO_PROTOCOL,(char *)"Early Data Accepted\n",NULL,0,NULL);
        } else {
            log(IO_PROTOCOL,(char *)"Early Data was NOT Accepted\n",NULL,0,NULL);
        }
    }
#endif
#if VERBOSITY >= IO_DEBUG
    if (expected->alpn)
    {
        if (received->alpn)
        {
             log(IO_DEBUG,(char *)"ALPN extension acknowledged by server\n",NULL,0,NULL);
        
        } else {
            log(IO_DEBUG,(char *)"Warning - ALPN extension NOT acknowledged by server\n",NULL,0,NULL);
        }
    }

    if (expected->server_name)
    {
        if (received->server_name)
        {
            log(IO_DEBUG,(char *)"Server Name acknowledged\n",NULL,0,NULL);
        } else {
            log(IO_DEBUG,(char *)"Server Name NOT acknowledged\n",NULL,0,NULL);
        }
    }
    if (expected->max_frag_length)
    {
        if (received->max_frag_length)
        {
            log(IO_DEBUG,(char *)"Max frag length request acknowledged\n",NULL,0,NULL);
        } else {
            log(IO_DEBUG,(char *)"Max frag length request NOT acknowledged\n",NULL,0,NULL);
        }
    }
#endif
}

// log server hello outputs
void logServerHello(int cipher_suite,int pskid,octad *PK,octad *CK)
{
#if VERBOSITY >= IO_DEBUG
    log(IO_DEBUG,(char *)"Parsing serverHello\n",NULL,0,NULL);
    logCipherSuite(cipher_suite);
    if (pskid>=0) log(IO_DEBUG,(char *)"PSK Identity= ",(char *)"%d",pskid,NULL);
    if (PK->len>0) {
        log(IO_DEBUG,(char *)"Server Public Key= ",NULL,0,PK);//OCT_output(PK);
    }
    if (CK->len>0) {
        log(IO_DEBUG,(char *)"Cookie= ",NULL,0,CK); //OCT_output(CK);
    }
    log(IO_DEBUG,(char *)"\n",NULL,0,NULL);
#endif
}

// log ticket details
void logTicket(ticket *T)
{
#if VERBOSITY >= IO_DEBUG
    log(IO_DEBUG,(char *)"\nParsing Ticket\n",NULL,0,NULL);
    log(IO_DEBUG,(char *)"Ticket = ",NULL,0,&T->TICK); 
    unsign32 minutes=T->lifetime/60;
    log(IO_DEBUG,(char *)"life time in minutes = ",(char *)"%d",minutes,NULL);
    log(IO_DEBUG,(char *)"PSK = ",NULL,0,&T->PSK); 
    log(IO_DEBUG,(char *)"max_early_data = ",(char *)"%d",T->max_early_data,NULL);
    log(IO_DEBUG,(char *)"\n",NULL,0,NULL);
#endif
}

// log a certificate in base64

void logCert(octad *CERT)
{
    char b[5004];
    log(IO_DEBUG,(char *)"-----BEGIN CERTIFICATE----- \n",NULL,0,NULL);
#if VERBOSITY >= IO_DEBUG
    OCT_output_base64(CERT,5000,b);
#endif
    log(IO_DEBUG,(char *)"",b,0,NULL);
    log(IO_DEBUG,(char *)"-----END CERTIFICATE----- \n",NULL,0,NULL);
}

// Construct Distinguished Name from DER encoding
static int make_dn(octad *DN,octad *DER) {
    int i,c,len,n=0;
    DN->val[n++]='{';
    c=X509_find_entity_property(DER,&X509_MN,0,&len);
    for (i=0;i<len;i++) {
        DN->val[n++]=DER->val[c+i];
    }

    DN->val[n++]=',';
    c=X509_find_entity_property(DER,&X509_UN,0,&len);
    for (i=0;i<len;i++) {
        DN->val[n++]=DER->val[c+i];
    }

    DN->val[n++]=',';
    c=X509_find_entity_property(DER,&X509_ON,0,&len);
    for (i=0;i<len;i++) {
        DN->val[n++]=DER->val[c+i];
    }

    DN->val[n++]=',';
    c=X509_find_entity_property(DER,&X509_CN,0,&len);
    for (i=0;i<len;i++) {
        DN->val[n++]=DER->val[c+i];
    }
    DN->val[n++]='}';
    DN->val[n++]=0;
    DN->len=n;
    return n;
}

// log certificate details
void logCertDetails(octad *PUBKEY,pktype pk,octad *SIG,pktype sg,octad *ISSUER,octad *SUBJECT)
{
#if VERBOSITY >= IO_PROTOCOL
    log(IO_DEBUG,(char *)"Parsing Certificate\n",NULL,0,NULL);
    log(IO_DEBUG,(char *)"Signature on Certificate is ",NULL,0,SIG); 
    if (sg.type==X509_ECC)
    {
        log(IO_PROTOCOL,(char *)"Certificate signature is ECDSA - ",NULL,0,NULL);
        if (sg.curve==USE_NIST256)
            log(IO_PROTOCOL,(char *)"Curve is SECP256R1 ",NULL,0,NULL);
        if (sg.curve==USE_NIST384)
            log(IO_PROTOCOL,(char *)"Curve is SECP384R1 ",NULL,0,NULL);
        if (sg.curve==USE_NIST521)
            log(IO_PROTOCOL,(char *)"Curve is SECP521R1 ",NULL,0,NULL);
        if (sg.hash == X509_H256) log(IO_PROTOCOL,(char *)"Hashed with SHA256\n",NULL,0,NULL);
        if (sg.hash == X509_H384) log(IO_PROTOCOL,(char *)"Hashed with SHA384\n",NULL,0,NULL);
        if (sg.hash == X509_H512) log(IO_PROTOCOL,(char *)"Hashed with SHA512\n",NULL,0,NULL);
    }
    if (sg.type==X509_ECD)
    {
       log(IO_PROTOCOL,(char *)"Certificate signature is EdDSA - ",NULL,0,NULL);
        if (sg.curve==USE_ED25519)
            log(IO_PROTOCOL,(char *)"Curve is ED25519\n",NULL,0,NULL);
        if (sg.curve==USE_ED448)
            log(IO_PROTOCOL,(char *)"Curve is ED448\n",NULL,0,NULL);
    }
    if (sg.type==X509_RSA)
        log(IO_PROTOCOL,(char *)"Certificate signature is RSA of length (bits) ",(char *)"%d",8*SIG->len/*sg.curve*/,NULL);

    if (sg.type==X509_DLM)
        log(IO_PROTOCOL,(char *)"Certificate signature is Post Quantum (ML-DSA) of length (bits) ",(char *)"%d",8*SIG->len/*sg.curve*/,NULL);

    if (sg.type==X509_HY1)
        log(IO_PROTOCOL,(char *)"Certificate signature is Hybrid of length (bits) ",(char *)"%d",8*SIG->len/*sg.curve*/,NULL);

#ifdef SQISIGN_TEST
    if (sg.type==X509_SQI)
        log(IO_PROTOCOL,(char *)"Certificate signature is Post Quantum (SQISIGN) of length (bits) ",(char *)"%d",8*SIG->len/*sg.curve*/,NULL);

    if (sg.type==X509_HY2)
        log(IO_PROTOCOL,(char *)"Certificate signature is Hybrid (SQISIGN+EDDSA) of length (bits) ",(char *)"%d",8*SIG->len/*sg.curve*/,NULL);
#endif

    log(IO_DEBUG,(char *)"Public key from Certificate is ",NULL,0,PUBKEY); 
    if (pk.type==X509_ECC)
    {
        log(IO_PROTOCOL,(char *)"Certificate public key is ECC - ",NULL,0,NULL);
        if (pk.curve==USE_NIST256)
            log(IO_PROTOCOL,(char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST384)
            log(IO_PROTOCOL,(char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST521)
            log(IO_PROTOCOL,(char *)"Curve is SECP521R1\n",NULL,0,NULL);
    }
    if (pk.type==X509_ECD)
    {
        log(IO_PROTOCOL,(char *)"Certificate public key is ECC - ",NULL,0,NULL);
        if (pk.curve==USE_ED25519)
            log(IO_PROTOCOL,(char *)"Curve is ED25519\n",NULL,0,NULL);
        if (pk.curve==USE_ED448)
            log(IO_PROTOCOL,(char *)"Curve is ED448\n",NULL,0,NULL);
    }
    if (pk.type==X509_RSA)
        log(IO_PROTOCOL,(char *)"Certificate public key is RSA of length (bits) ",(char *)"%d",8*PUBKEY->len/*pk.curve*/,NULL);
    
    if (pk.type==X509_DLM)
        log(IO_PROTOCOL,(char *)"Certificate public key is Post Quantum (ML-DSA) of length (bits) ",(char *)"%d",8*PUBKEY->len/*pk.curve*/,NULL);

    if (pk.type==X509_HY1)
        log(IO_PROTOCOL,(char *)"Certificate public key is Hybrid (MLDSA+ECDSA) of length (bits) ",(char *)"%d",8*PUBKEY->len/*pk.curve*/,NULL);


#ifdef SQISIGN_TEST
    if (pk.type==X509_SQI)
        log(IO_PROTOCOL,(char *)"Certificate public key is Post Quantum (SQISIGN) of length (bits) ",(char *)"%d",8*PUBKEY->len/*pk.curve*/,NULL);

    if (pk.type==X509_HY2)
        log(IO_PROTOCOL,(char *)"Certificate public key is Hybrid (SQISIGN+EDDSA) of length (bits) ",(char *)"%d",8*PUBKEY->len/*pk.curve*/,NULL);
#endif

    char dn[256];
    octad DN={0,sizeof(dn),dn};
    make_dn(&DN,ISSUER);

    log(IO_DEBUG,(char *)"Issuer is  ",(char *)DN.val,0,NULL);
    make_dn(&DN,SUBJECT);
    log(IO_DEBUG,(char *)"Subject is ",(char *)DN.val,0,NULL);
    //log(IO_DEBUG,(char *)"Issuer is  ",(char *)ISSUER->val,0,NULL);
    //log(IO_DEBUG,(char *)"Subject is ",(char *)SUBJECT->val,0,NULL);
#endif
}

// log alert
void logAlert(int detail)
{
#if VERBOSITY >= IO_PROTOCOL
    switch (detail)
    {
    case 0 :
        log(IO_PROTOCOL,(char *)"Close notify\n",NULL,0,NULL);
        break;
    case 10 :
        log(IO_PROTOCOL,(char *)"Unexpected Message\n",NULL,0,NULL);
        break;
    case 20 :
        log(IO_PROTOCOL,(char *)"Bad record mac\n",NULL,0,NULL);
        break;
    case 22 :
        log(IO_PROTOCOL,(char *)"Record overflow\n",NULL,0,NULL);
        break;
    case 40 :
        log(IO_PROTOCOL,(char *)"Handshake Failure (not TLS1.3?)\n",NULL,0,NULL);
        break;
    case 42 :
        log(IO_PROTOCOL,(char *)"Bad certificate\n",NULL,0,NULL);
        break;
    case 43 :
        log(IO_PROTOCOL,(char *)"Unsupported certificate\n",NULL,0,NULL);
        break;
    case 44 :
        log(IO_PROTOCOL,(char *)"Certificate revoked\n",NULL,0,NULL);
        break;
    case 45 :
        log(IO_PROTOCOL,(char *)"Certificate expired\n",NULL,0,NULL);
        break;
    case 46 :
        log(IO_PROTOCOL,(char *)"Certificate unknown\n",NULL,0,NULL);
        break;
    case 47 :
        log(IO_PROTOCOL,(char *)"Illegal parameter\n",NULL,0,NULL);
        break;
    case 48 :
        log(IO_PROTOCOL,(char *)"Unknown CA\n",NULL,0,NULL);
        break;
    case 49 :
        log(IO_PROTOCOL,(char *)"Access denied\n",NULL,0,NULL);
        break;
    case 50 :
        log(IO_PROTOCOL,(char *)"Decode error\n",NULL,0,NULL);
        break;
    case 51 :
        log(IO_PROTOCOL,(char *)"Decrypt error\n",NULL,0,NULL);
        break;
    case 70 :
        log(IO_PROTOCOL,(char *)"Protocol version\n",NULL,0,NULL);
        break;
    case 71 :
        log(IO_PROTOCOL,(char *)"Insufficient security\n",NULL,0,NULL);
        break;
    case 80 :
        log(IO_PROTOCOL,(char *)"Internal error\n",NULL,0,NULL);
        break;
    case 86 :
        log(IO_PROTOCOL,(char *)"Inappropriate fallback\n",NULL,0,NULL);
        break;
    case 90 :
        log(IO_PROTOCOL,(char *)"User cancelled\n",NULL,0,NULL);
        break;
    case 109 :
        log(IO_PROTOCOL,(char *)"Missing Extension\n",NULL,0,NULL);
        break;
    case 110 :
        log(IO_PROTOCOL,(char *)"Unsupported Extension\n",NULL,0,NULL);
        break;
    case 112 :
        log(IO_PROTOCOL,(char *)"Unrecognised name\n",NULL,0,NULL);
        break;
    case 113 :
        log(IO_PROTOCOL,(char *)"Bad certificate status response\n",NULL,0,NULL);
        break;
    case 115 :
        log(IO_PROTOCOL,(char *)"Unknown PSK identity \n",NULL,0,NULL);
        break;
    case 116 :
        log(IO_PROTOCOL,(char *)"Certificate required\n",NULL,0,NULL);
        break;
    case 120 :
        log(IO_PROTOCOL,(char *)"No application protocol\n",NULL,0,NULL);
        break;
    default:
        log(IO_PROTOCOL,(char *)"Unrecognised alert\n",NULL,0,NULL);
        break;
    }
#endif
}

// process server function return
void logServerResponse(ret r)
{
    int rtn=r.err;
    if (rtn==0) return;
#if VERBOSITY >= IO_DEBUG
    if (rtn<0)
    { // fatal errors - after logging we will send a server alert and close connection
        switch (rtn)
        { 
        case NOT_TLS1_3:
            log(IO_DEBUG,(char *)"Not TLS1.3\n",NULL,0,NULL);
            break;
        case ID_MISMATCH:
            log(IO_DEBUG,(char *)"Identity Mismatch\n",NULL,0,NULL);
            break;
        case UNRECOGNIZED_EXT:
            log(IO_DEBUG,(char *)"Unrecognised Extension\n",NULL,0,NULL);
            break;
        case BAD_HELLO:
            log(IO_DEBUG,(char *)"Malformed Hello\n",NULL,0,NULL);
            break;
        case WRONG_MESSAGE:
            log(IO_DEBUG,(char *)"Message received out-of-order\n",NULL,0,NULL);
            break;
        case BAD_CERT_CHAIN:
            log(IO_DEBUG,(char *)"Bad Certificate Chain\n",NULL,0,NULL);
            break;
        case MISSING_REQUEST_CONTEXT:
            log(IO_DEBUG,(char *)"Missing Request Context\n",NULL,0,NULL);
            break;
        case AUTHENTICATION_FAILURE:
            log(IO_DEBUG,(char *)"Authentication Failure\n",NULL,0,NULL);
            break;
        case BAD_RECORD:
            log(IO_DEBUG,(char *)"Malformed Record received (max size exceeded?)\n",NULL,0,NULL);
            break;
        case BAD_TICKET:
            log(IO_DEBUG,(char *)"Malformed Ticket received\n",NULL,0,NULL);
            break;
        case NOT_EXPECTED:
            log(IO_DEBUG,(char *)"Unexpected message/extension\n",NULL,0,NULL);
            break;
        case CA_NOT_FOUND:
            log(IO_DEBUG,(char *)"Certificate Authority not found\n",NULL,0,NULL);
            break;
        case CERT_OUTOFDATE:
            log(IO_DEBUG,(char *)"Certificate is out of date\n",NULL,0,NULL);
            break;
        case MEM_OVERFLOW:
            log(IO_DEBUG,(char *)"Memory overflow\n",NULL,0,NULL);
            break;
        case FORBIDDEN_EXTENSION:
            log(IO_DEBUG,(char *)"Forbidden extension found\n",NULL,0,NULL);
            break;
        case MAX_EXCEEDED:
            log(IO_DEBUG,(char *)"Maximum record size exceeded\n",NULL,0,NULL);
            break;
        case CERT_VERIFY_FAIL:
            log(IO_DEBUG,(char *)"Certificate verification failure\n",NULL,0,NULL);
            break;
        case BAD_HANDSHAKE:
            log(IO_DEBUG,(char *)"Handshake protocol failure\n",NULL,0,NULL);
            break;
        case BAD_REQUEST_UPDATE:
            log(IO_DEBUG,(char *)"Bad Key update request\n",NULL,0,NULL);
            break;
        case MISSING_EXTENSIONS:
            log(IO_DEBUG,(char *)"Some extension(s) are missing\n",NULL,0,NULL);
            break;
        case BAD_MESSAGE:
            log(IO_DEBUG,(char *)"Malformed Message received\n",NULL,0,NULL);
            break;
        case EMPTY_CERT_CHAIN:
            log(IO_DEBUG,(char *)"Client Certificate required\n",NULL,0,NULL);
            break;
        default:
            log(IO_DEBUG,(char *)"Unknown Error\n",NULL,0,NULL);
            break;
        }
    } else { // server response requiring client action 
        switch (rtn)
        {
        case TIMED_OUT :
            log(IO_DEBUG,(char *)"Time Out\n",NULL,0,NULL);
            break;
        case ALERT :
            log(IO_DEBUG,(char *)"Alert received from server\n",NULL,0,NULL);  // received an alert 
            break;
        default: break;
        }
    }
#endif
}
