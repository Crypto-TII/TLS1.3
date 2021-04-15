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

// log server hello outputs
void logServerHello(int cipher_suite,int kex,int pskid,octad *PK,octad *CK)
{
    logger((char *)"\nParsing serverHello\n",NULL,0,NULL);
    logger((char *)"cipher suite= ",(char *)"%x",cipher_suite,NULL);
    logger((char *)"Key exchange algorithm= ",(char *)"%x",kex,NULL);
    if (pskid>=0) logger((char *)"PSK Identity= ",(char *)"%d",pskid,NULL);
    if (PK->len>0) {
        logger((char *)"Server Public Key= ",NULL,0,PK);//OCT_output(PK);
    }
    if (CK->len>0) {
        logger((char *)"Cookie= ",NULL,0,CK); //OCT_output(CK);
    }
    logger((char *)"\n",NULL,0,NULL);
}

// log ticket details
void logTicket(int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octad *NONCE,octad *ETICK)
{
    logger((char *)"\nParsing Ticket\n",NULL,0,NULL);
    unsign32 minutes=lifetime/60;
    logger((char *)"life time in minutes = ",(char *)"%d",minutes,NULL);
    logger((char *)"Age obfuscator = ",(char *)"%08x",age_obfuscator,NULL);
    logger((char *)"Nonce = ",NULL,0,NONCE); 
    logger((char *)"Ticket = ",NULL,0,ETICK); 
    logger((char *)"max_early_data = ",(char *)"%d",max_early_data,NULL);
    logger((char *)"\n",NULL,0,NULL);
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

// process server function return
void logServerResponse(int rtn,octad *O)
{
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
        case TIME_OUT :
            logger((char *)"Time Out\n",NULL,0,NULL);
            break;
        case HANDSHAKE_RETRY :
            logger((char *)"Handshake Retry Request\n",NULL,0,NULL);
            break;
        case ALERT :
            logger((char *)"Alert received from server - ",NULL,0,O);  // received an alert - close connection
            break;
        case STRANGE_EXTENSION:
            logger((char *)"Strange Extension Detected\n",NULL,0,NULL);
            break;      
        default: break;
        }
    }
}
