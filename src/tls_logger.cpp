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
// undefine LOGGER in tls1_3.h to save space

void logger(char *preamble,char *string,unsign32 info,octad *O)
{
#if VERBOSITY>IO_NONE    

    myprintf(preamble);

    if (O!=NULL)
    {
        char buff[128];
        bool res=OCT_output_hex(O,120,buff);
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
            char w[10];
            sprintf(w,string,info);
            myprintf(w);
        }
        myprintf((char *)"\n");
        return;
    }
 
#endif
}

void logCipherSuite(int cipher_suite)
{
#if VERBOSITY >= IO_DEBUG
    switch (cipher_suite)
    {
    case TLS_AES_128_GCM_SHA256:
        logger((char *)"Cipher Suite is TLS_AES_128_GCM_SHA256\n",NULL,0,NULL);
        break;
    case TLS_AES_256_GCM_SHA384:
        logger((char *)"Cipher Suite is TLS_AES_256_GCM_SHA384\n",NULL,0,NULL);   
        break;
    case TLS_CHACHA20_POLY1305_SHA256:
        logger((char *)"Cipher Suite is TLS_CHACHA20_POLY1305_SHA256\n",NULL,0,NULL);   
        break;
    default:
        logger((char *)"Non-standard Cipher Suite\n",NULL,0,NULL);   
        break;
    }
#endif
}

void logKeyExchange(int kex)
{
    switch (kex)
    {
    case X25519:
        logger((char *)"Key Exchange Group is X25519\n",NULL,0,NULL);
        break;
    case SECP256R1:
        logger((char *)"Key Exchange Group is SECP256R1\n",NULL,0,NULL);   
        break;
    case SECP384R1:
        logger((char *)"Key Exchange Group is SECP384R1\n",NULL,0,NULL);   
        break;
    default:
        logger((char *)"Non-standard Key Exchange Group\n",NULL,0,NULL);   
        break;
    }
}

void logSigAlg(int sigAlg)
{
#if VERBOSITY >= IO_DEBUG
    switch (sigAlg)
    {
    case ECDSA_SECP256R1_SHA256:
        logger((char *)"Signature Algorithm is ECDSA_SECP256R1_SHA256\n",NULL,0,NULL);
        break;
    case RSA_PSS_RSAE_SHA256:
        logger((char *)"Signature Algorithm is RSA_PSS_RSAE_SHA256\n",NULL,0,NULL);   
        break;
    case RSA_PKCS1_SHA256:
        logger((char *)"Signature Algorithm is RSA_PKCS1_SHA256\n",NULL,0,NULL);   
        break;
    case ECDSA_SECP384R1_SHA384:
        logger((char *)"Signature Algorithm is ECDSA_SECP384R1_SHA384\n",NULL,0,NULL);
        break;
    case RSA_PSS_RSAE_SHA384:
        logger((char *)"Signature Algorithm is RSA_PSS_RSAE_SHA384\n",NULL,0,NULL);   
        break;
    case RSA_PKCS1_SHA384:
        logger((char *)"Signature Algorithm is RSA_PKCS1_SHA384\n",NULL,0,NULL);   
        break;
    case RSA_PSS_RSAE_SHA512:
        logger((char *)"Signature Algorithm is RSA_PSS_RSAE_SHA512\n",NULL,0,NULL);   
        break;
    case RSA_PKCS1_SHA512:
        logger((char *)"Signature Algorithm is RSA_PKCS1_SHA512\n",NULL,0,NULL);   
        break;
    case ED25519:
        logger((char *)"Signature Algorithm is ED25519\n",NULL,0,NULL);   
        break;
    default:
        logger((char *)"Non-standard Signature Algorithm\n",NULL,0,NULL);   
        break;
    }
#endif
}

// log Encrypted Extensions Responses
void logEncExt(ee_expt *expected,ee_resp *received)
{
#if VERBOSITY >= IO_PROTOCOL
    if (expected->early_data)
    {
        if (received->early_data)
        {
            logger((char *)"Early Data Accepted\n",NULL,0,NULL);
        } else {
            logger((char *)"Early Data was NOT Accepted\n",NULL,0,NULL);
        }
    }
#endif
    if (expected->alpn && !received->alpn)
    {
#if VERBOSITY >= IO_PROTOCOL
        logger((char *)"Warning - ALPN extension NOT acknowledged by server\n",NULL,0,NULL);
#endif
    } else {
#if VERBOSITY >= IO_DEBUG
        logger((char *)"ALPN extension acknowledged by server\n",NULL,0,NULL);
#endif
    }

#if VERBOSITY >= IO_DEBUG
    if (expected->server_name && !received->server_name)
    {
        logger ((char *)"Server Name NOT acknowledged\n",NULL,0,NULL);
    } else {
        logger ((char *)"Server Name acknowledged\n",NULL,0,NULL);
    }
#endif
#if VERBOSITY >= IO_DEBUG
    if (expected->max_frag_length && !received->max_frag_length)
    {
        logger ((char *)"Max frag length request NOT acknowledged\n",NULL,0,NULL);
    } else {
        logger ((char *)"Max frag length request acknowledged\n",NULL,0,NULL);
    }
#endif
}

// log server hello outputs
void logServerHello(int cipher_suite,int kex,int pskid,octad *PK,octad *CK)
{
#if VERBOSITY >= IO_DEBUG
    logger((char *)"Parsing serverHello\n",NULL,0,NULL);
    logCipherSuite(cipher_suite);
    logKeyExchange(kex);
    if (pskid>=0) logger((char *)"PSK Identity= ",(char *)"%d",pskid,NULL);
    if (PK->len>0) {
        logger((char *)"Server Public Key= ",NULL,0,PK);//OCT_output(PK);
    }
    if (CK->len>0) {
        logger((char *)"Cookie= ",NULL,0,CK); //OCT_output(CK);
    }
    logger((char *)"\n",NULL,0,NULL);
#endif
}

// log ticket details
void logTicket(int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octad *NONCE,octad *ETICK)
{
#if VERBOSITY >= IO_DEBUG
    logger((char *)"\nParsing Ticket\n",NULL,0,NULL);
    unsign32 minutes=lifetime/60;
    logger((char *)"life time in minutes = ",(char *)"%d",minutes,NULL);
    logger((char *)"Age obfuscator = ",(char *)"%08x",age_obfuscator,NULL);
    logger((char *)"Nonce = ",NULL,0,NONCE); 
    logger((char *)"Ticket = ",NULL,0,ETICK); 
    logger((char *)"max_early_data = ",(char *)"%d",max_early_data,NULL);
    logger((char *)"\n",NULL,0,NULL);
#endif
}

// log a certificate in base64

void logCert(octad *CERT)
{
    char b[5004];
    logger((char *)"-----BEGIN CERTIFICATE----- \n",NULL,0,NULL);
    OCT_output_base64(CERT,5000,b);
    logger((char *)"",b,0,NULL);
    logger((char *)"-----END CERTIFICATE----- \n",NULL,0,NULL);
}


// log certificate details
void logCertDetails(char *txt,octad *PUBKEY,pktype pk,octad *SIG,pktype sg,octad *ISSUER,octad *SUBJECT)
{
    logger(txt,NULL,0,NULL);
    logger((char *)"Signature is ",NULL,0,SIG); 
    if (sg.type==X509_ECC)
    {
        logger((char *)"ECC signature ",NULL,0,NULL);
        if (sg.curve==USE_NIST256)
            logger((char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST384)
            logger((char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST521)
            logger((char *)"Curve is SECP521R1\n",NULL,0,NULL);
        if (sg.hash == X509_H256) logger((char *)"Hashed with SHA256\n",NULL,0,NULL);
        if (sg.hash == X509_H384) logger((char *)"Hashed with SHA384\n",NULL,0,NULL);
        if (sg.hash == X509_H512) logger((char *)"Hashed with SHA512\n",NULL,0,NULL);
    }
    if (sg.type==X509_RSA)
        logger((char *)"RSA signature of length ",(char *)"%d",sg.curve,NULL);

    logger((char *)"Public key= ",NULL,0,PUBKEY); 
    if (pk.type==X509_ECC)
    {
        logger((char *)"ECC public key ",NULL,0,NULL);
        if (pk.curve==USE_NIST256)
            logger((char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST384)
            logger((char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST521)
            logger((char *)"Curve is SECP521R1\n",NULL,0,NULL);
    }
    if (pk.type==X509_RSA)
        logger((char *)"RSA public key of length ",(char *)"%d",pk.curve,NULL);
    
    logger((char *)"Issuer is  ",(char *)ISSUER->val,0,NULL);
    logger((char *)"Subject is ",(char *)SUBJECT->val,0,NULL);
}

// log alert
void logAlert(int detail)
{
#if VERBOSITY >= IO_PROTOCOL
    switch (detail)
    {
    case 0 :
        logger((char *)"Close notify\n",NULL,0,NULL);
        break;
    case 10 :
        logger((char *)"Unexpected Message\n",NULL,0,NULL);
        break;
    case 20 :
        logger((char *)"Bad record mac\n",NULL,0,NULL);
        break;
    case 22 :
        logger((char *)"Record overflow\n",NULL,0,NULL);
        break;
    case 40 :
        logger((char *)"Handshake Failure (not TLS1.3?)\n",NULL,0,NULL);
        break;
    case 42 :
        logger((char *)"Bad certificate\n",NULL,0,NULL);
        break;
    case 43 :
        logger((char *)"Unsupported certificate\n",NULL,0,NULL);
        break;
    case 44 :
        logger((char *)"Certificate revoked\n",NULL,0,NULL);
        break;
    case 45 :
        logger((char *)"Certificate expired\n",NULL,0,NULL);
        break;
    case 46 :
        logger((char *)"Certificate unknown\n",NULL,0,NULL);
        break;
    case 47 :
        logger((char *)"Illegal parameter\n",NULL,0,NULL);
        break;
    case 48 :
        logger((char *)"Unknown CA\n",NULL,0,NULL);
        break;
    case 49 :
        logger((char *)"Access denied\n",NULL,0,NULL);
        break;
    case 50 :
        logger((char *)"Decode error\n",NULL,0,NULL);
        break;
    case 51 :
        logger((char *)"Decrypt error\n",NULL,0,NULL);
        break;
    case 70 :
        logger((char *)"Protocol version\n",NULL,0,NULL);
        break;
    case 71 :
        logger((char *)"Insufficient security\n",NULL,0,NULL);
        break;
    case 80 :
        logger((char *)"Internal error\n",NULL,0,NULL);
        break;
    case 86 :
        logger((char *)"Inappropriate fallback\n",NULL,0,NULL);
        break;
    case 90 :
        logger((char *)"User cancelled\n",NULL,0,NULL);
        break;
    case 109 :
        logger((char *)"Missing Extension\n",NULL,0,NULL);
        break;
    case 110 :
        logger((char *)"Unsupported Extension\n",NULL,0,NULL);
        break;
    case 112 :
        logger((char *)"Unrecognised name\n",NULL,0,NULL);
        break;
    case 113 :
        logger((char *)"Bad certificate status response\n",NULL,0,NULL);
        break;
    case 115 :
        logger((char *)"Unknown PSK identity \n",NULL,0,NULL);
        break;
    case 116 :
        logger((char *)"Certificate required\n",NULL,0,NULL);
        break;
    case 120 :
        logger((char *)"No application protocol\n",NULL,0,NULL);
        break;
    default:
        logger((char *)"Unrecognised alert\n",NULL,0,NULL);
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
            logger((char *)"Not TLS1.3\n",NULL,0,NULL);
            break;
        case BAD_CERT_CHAIN:
            logger((char *)"Bad Certificate Chain\n",NULL,0,NULL);
            break;
        case ID_MISMATCH:
            logger((char *)"Identity Mismatch\n",NULL,0,NULL);
            break;
        case UNRECOGNIZED_EXT:
            logger((char *)"Unrecognised Extension\n",NULL,0,NULL);
            break;
        case BAD_HELLO:
            logger((char *)"Malformed Hello\n",NULL,0,NULL);
            break;
        case WRONG_MESSAGE:
            logger((char *)"Message received out-of-order\n",NULL,0,NULL);
            break;
        case MISSING_REQUEST_CONTEXT:
            logger((char *)"Missing Request Context\n",NULL,0,NULL);
            break;
        case AUTHENTICATION_FAILURE:
            logger((char *)"Authentication Failure\n",NULL,0,NULL);
            break;
        case BAD_RECORD:
            logger((char *)"Malformed Record received (max size exceeded?)\n",NULL,0,NULL);
            break;
        case BAD_TICKET:
            logger((char *)"Malformed Ticket received\n",NULL,0,NULL);
            break;
        default:
            logger((char *)"Unknown Error\n",NULL,0,NULL);
            break;
        }
    } else { // server response requiring client action 
        switch (rtn)
        {
        case TIMED_OUT :
            logger((char *)"Time Out\n",NULL,0,NULL);
            break;
        case ALERT :
            logger((char *)"Alert received from server\n",NULL,0,NULL);  // received an alert 
            break;
        default: break;
        }
    }
#endif
}
