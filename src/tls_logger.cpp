// 
// Log protocol progress
//
#include "tls_logger.h"

#ifdef CORE_ARDUINO
#include <Arduino.h>
#endif

// all terminal output redirected here
void myprintf(char *s)
{
#ifdef CORE_ARDUINO
    Serial.print(s);
#else
    printf("%s",s);
#endif
}

// log debug string and info or Octet
// if string is not NULL, output info, with format in string
// if O is not null, output octet in hex.
// undefine LOGGER in tls1_3.h to save space

#define VERBOSITY IO_DEBUG

void logger(int level,char *preamble,char *string,unsign32 info,octet *O)
{
#if VERBOSITY>IO_NONE    

    if (VERBOSITY>=level)
    {
        myprintf(preamble);

        if (O!=NULL)
        {
            OCT_output(O);
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
    }
#endif
}

// log server hello outputs
void logServerHello(int level,int cipher_suite,int kex,int pskid,octet *PK,octet *CK)
{
    logger(level,(char *)"\nParsing serverHello\n",NULL,0,NULL);
    logger(level,(char *)"cipher suite= ",(char *)"%x",cipher_suite,NULL);
    logger(level,(char *)"Key exchange algorithm= ",(char *)"%x",kex,NULL);
    if (pskid>0) logger(level,(char *)"PSK Identity= ",(char *)"%d",pskid,NULL);
    if (PK->len>0) {
        logger(level,(char *)"Server Public Key= ",NULL,0,PK);//OCT_output(PK);
    }
    if (CK->len>0) {
        logger(level,(char *)"Cookie= ",NULL,0,CK); //OCT_output(CK);
    }
    logger(level,(char *)"\n",NULL,0,NULL);
}

// log ticket details
void logTicket(int level,int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octet *NONCE,octet *ETICK)
{
    logger(level,(char *)"\nParsing Ticket\n",NULL,0,NULL);
    unsign32 minutes=lifetime/60;
    logger(level,(char *)"life time in minutes = ",(char *)"%d",minutes,NULL);
    logger(level,(char *)"Age obfuscator = ",(char *)"%08x",age_obfuscator,NULL);
    logger(level,(char *)"Nonce = ",NULL,0,NONCE); 
    logger(level,(char *)"Ticket = ",NULL,0,ETICK); 
    logger(level,(char *)"max_early_data = ",(char *)"%d",max_early_data,NULL);
    logger(level,(char *)"\n",NULL,0,NULL);
}

// log a certificate in base64
/*
void logCert(int level,octet *CERT)
{
    char b[TLS_MAX_SIGNED_CERT_B64];
    logger(level,(char *)"-----BEGIN CERTIFICATE----- \n",NULL,0,NULL);
    OCT_tobase64(b,CERT);
    logger(level,(char *)"",b,0,NULL);
    logger(level,(char *)"-----END CERTIFICATE----- \n",NULL,0,NULL);
}
*/

// log certificate details
void logCertDetails(int level,char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT)
{
    logger(level,txt,NULL,0,NULL);
    logger(level,(char *)"\nSignature is ",NULL,0,SIG); 
    if (sg.type==X509_ECC)
    {
        logger(level,(char *)"ECC signature ",NULL,0,NULL);
        if (sg.curve==USE_NIST256)
            logger(level,(char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST384)
            logger(level,(char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST521)
            logger(level,(char *)"Curve is SECP521R1\n",NULL,0,NULL);
        if (sg.hash == X509_H256) logger(level,(char *)"Hashed with SHA256\n",NULL,0,NULL);
        if (sg.hash == X509_H384) logger(level,(char *)"Hashed with SHA384\n",NULL,0,NULL);
        if (sg.hash == X509_H512) logger(level,(char *)"Hashed with SHA512\n",NULL,0,NULL);
    }
    if (sg.type==X509_RSA)
        logger(level,(char *)"RSA signature of length ",(char *)"%d",sg.curve,NULL);

    logger(level,(char *)"Public key= ",NULL,0,PUBKEY); 
    if (pk.type==X509_ECC)
    {
        logger(level,(char *)"ECC public key ",NULL,0,NULL);
        if (pk.curve==USE_NIST256)
            logger(level,(char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST384)
            logger(level,(char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST521)
            logger(level,(char *)"Curve is SECP521R1\n",NULL,0,NULL);
    }
    if (pk.type==X509_RSA)
        logger(level,(char *)"RSA public key of length ",(char *)"%d",pk.curve,NULL);
    
    logger(level,(char *)"Issuer is  ",(char *)ISSUER->val,0,NULL);
    logger(level,(char *)"Subject is ",(char *)SUBJECT->val,0,NULL);
}

// process server function return
void logServerResponse(int level,int rtn,octet *O)
{
    if (rtn<0)
    { // fatal errors - after logging we will send a server alert and close connection
        switch (rtn)
        { 
        case NOT_TLS1_3:
            logger(level,(char *)"Not TLS1.3\n",NULL,0,NULL);
            break;
        case BAD_CERT_CHAIN:
            logger(level,(char *)"Bad Certificate Chain\n",NULL,0,NULL);
            break;
        case ID_MISMATCH:
            logger(level,(char *)"Identity Mismatch\n",NULL,0,NULL);
            break;
        case UNRECOGNIZED_EXT:
            logger(level,(char *)"Unrecognised Extension\n",NULL,0,NULL);
            break;
        case BAD_HELLO:
            logger(level,(char *)"Malformed Hello\n",NULL,0,NULL);
            break;
        case WRONG_MESSAGE:
            logger(level,(char *)"Message received out-of-order\n",NULL,0,NULL);
            break;
        case MISSING_REQUEST_CONTEXT:
            logger(level,(char *)"Missing Request Context\n",NULL,0,NULL);
            break;
        case AUTHENTICATION_FAILURE:
            logger(level,(char *)"Authentication Failure\n",NULL,0,NULL);
            break;
        case BAD_RECORD:
            logger(level,(char *)"Malformed Record received\n",NULL,0,NULL);
            break;
        case BAD_TICKET:
            logger(level,(char *)"Malformed Ticket received\n",NULL,0,NULL);
            break;
        default:
            logger(level,(char *)"Unknown Error\n",NULL,0,NULL);
            break;
        }
    } else { // server response requiring client action 
        switch (rtn)
        {
        case TIME_OUT :
            logger(level,(char *)"Time Out\n",NULL,0,NULL);
            break;
        case HANDSHAKE_RETRY :
            logger(level,(char *)"Handshake Retry Request\n",NULL,0,NULL);
            break;
        case ALERT :
            logger(level,(char *)"Alert received from server - ",NULL,0,O);  // received an alert - close connection
            break;
        case STRANGE_EXTENSION:
            logger(level,(char *)"Strange Extension Detected\n",NULL,0,NULL);
            break;      
        default: break;
        }
    }
}
