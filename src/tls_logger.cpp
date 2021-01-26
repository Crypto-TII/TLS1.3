// 
// Log protocol progress
//
#include "tls_logger.h"

// log debug string or info or Octet
// string and O should not both be non-NULL
// if O not null, then info indicates output as Hex or Ascii string
void logger(FILE *fp,char *preamble,char *string,unsign32 info,octet *O)
{
#ifdef LOGGER
    fprintf(fp,"%s",preamble);

    if (O!=NULL)
    {
        int len=O->len;
        char w[520];

        if (len>256)
        {
            fprintf(fp,"(truncated) ");
            O->len=200;
            OCT_toHex(O,w);
            O->len=len;    
        } else {
            OCT_toHex(O,w);
        } 
        fprintf(fp," %d %s\n",len,w);
    } 

    if (string!=NULL)
    {
        if (strlen(string)>6)
            fprintf(fp,"%s",string);
        else
            fprintf(fp,string,info);
        fprintf(fp,"\n");
    } 
#endif
}


void logServerHello(FILE *fp,int cipher_suite,int kex,int pskid,octet *PK,octet *CK)
{
    logger(fp,(char *)"\nParsing serverHello\n",NULL,0,NULL);
    logger(fp,(char *)"cipher suite= ",(char *)"%x",cipher_suite,NULL);
    logger(fp,(char *)"Key exchange algorithm= ",(char *)"%x",kex,NULL);
    if (pskid>0) logger(fp,(char *)"PSK Identity= ",(char *)"%d",pskid,NULL);
    if (PK->len>0) {
        logger(fp,(char *)"Server Public Key= ",NULL,0,PK);//OCT_output(PK);
    }
    if (CK->len>0) {
        logger(fp,(char *)"Cookie= ",NULL,0,CK); //OCT_output(CK);
    }
    logger(fp,(char *)"\n",NULL,0,NULL);
}


void logTicket(FILE *fp,int lifetime,unsign32 age_obfuscator,unsign32 max_early_data,octet *NONCE,octet *ETICK)
{
    logger(fp,(char *)"\nParsing Ticket\n",NULL,0,NULL);
    unsign32 minutes=lifetime/60;
    logger(fp,(char *)"life time in minutes = ",(char *)"%d",minutes,NULL);
    logger(fp,(char *)"Age obfuscator = ",(char *)"%08x",age_obfuscator,NULL);
    logger(fp,(char *)"Nonce = ",NULL,0,NONCE); 
    logger(fp,(char *)"Ticket = ",NULL,0,ETICK); 
    logger(fp,(char *)"max_early_data = ",(char *)"%d",max_early_data,NULL);
    logger(fp,(char *)"\n",NULL,0,NULL);
}

void logCert(FILE *fp,octet *CERT)
{
    char b[TLS_MAX_SIGNED_CERT_B64];
    logger(fp,(char *)"-----BEGIN CERTIFICATE----- \n",NULL,0,NULL);
    OCT_tobase64(b,CERT);
    logger(fp,(char *)"",b,0,NULL);
    logger(fp,(char *)"-----END CERTIFICATE----- \n",NULL,0,NULL);
}

void logCertDetails(FILE *fp,char *txt,octet *PUBKEY,pktype pk,octet *SIG,pktype sg,octet *ISSUER,octet *SUBJECT)
{
    logger(fp,txt,NULL,0,NULL);
    logger(fp,(char *)"\nSignature is ",NULL,0,SIG); 
    if (sg.type==X509_ECC)
    {
        logger(fp,(char *)"ECC signature ",NULL,0,NULL);
        if (sg.curve==USE_NIST256)
            logger(fp,(char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST384)
            logger(fp,(char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (sg.curve==USE_NIST521)
            logger(fp,(char *)"Curve is SECP521R1\n",NULL,0,NULL);
        if (sg.hash == X509_H256) logger(fp,(char *)"Hashed with SHA256\n",NULL,0,NULL);
        if (sg.hash == X509_H384) logger(fp,(char *)"Hashed with SHA384\n",NULL,0,NULL);
        if (sg.hash == X509_H512) logger(fp,(char *)"Hashed with SHA512\n",NULL,0,NULL);
    }
    if (sg.type==X509_RSA)
        logger(fp,(char *)"RSA signature of length ",(char *)"%d",sg.curve,NULL);

    logger(fp,(char *)"Public key= ",NULL,0,PUBKEY); 
    if (pk.type==X509_ECC)
    {
        logger(fp,(char *)"ECC public key ",NULL,0,NULL);
        if (pk.curve==USE_NIST256)
            logger(fp,(char *)"Curve is SECP256R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST384)
            logger(fp,(char *)"Curve is SECP384R1\n",NULL,0,NULL);
        if (pk.curve==USE_NIST521)
            logger(fp,(char *)"Curve is SECP521R1\n",NULL,0,NULL);
    }
    if (pk.type==X509_RSA)
        logger(fp,(char *)"RSA public key of length ",(char *)"%d",pk.curve,NULL);
    
    logger(fp,(char *)"Issuer is  ",(char *)ISSUER->val,0,NULL);
    logger(fp,(char *)"Subject is ",(char *)SUBJECT->val,0,NULL);
}

// process server function return
void logServerResponse(FILE *fp,int rtn,octet *O)
{
    if (rtn<0)
    { // fatal errors - send server alert and close connection
        switch (rtn)
        { 
        case NOT_TLS1_3:
            logger(fp,(char *)"Not TLS1.3\n",NULL,0,NULL);
            break;
        case ID_MISMATCH:
            logger(fp,(char *)"Identity Mismatch\n",NULL,0,NULL);
            break;
        case UNRECOGNIZED_EXT:
            logger(fp,(char *)"Unrecognised Extension\n",NULL,0,NULL);
            break;
        case BAD_HELLO:
            logger(fp,(char *)"Malformed Hello\n",NULL,0,NULL);
            break;
        case WRONG_MESSAGE:
            logger(fp,(char *)"Message received out-of-order\n",NULL,0,NULL);
            break;
        case MISSING_REQUEST_CONTEXT:
            logger(fp,(char *)"Missing Request Context\n",NULL,0,NULL);
            break;
        case AUTHENTICATION_FAILURE:
            logger(fp,(char *)"Authentication Failure\n",NULL,0,NULL);
            break;
        case BAD_RECORD:
            logger(fp,(char *)"Malformed Record received\n",NULL,0,NULL);
            break;
        case BAD_TICKET:
            logger(fp,(char *)"Malformed Ticket received\n",NULL,0,NULL);
            break;
        default:
            logger(fp,(char *)"Unknown Error\n",NULL,0,NULL);
            break;
        }
    } else { // server response requiring client action 
        switch (rtn)
        {
        case TIME_OUT :
            logger(fp,(char *)"Time Out\n",NULL,0,NULL);
            break;
        case HANDSHAKE_RETRY :
            logger(fp,(char *)"Handshake Retry Request\n",NULL,0,NULL);
            break;
        case ALERT :
            logger(fp,(char *)"Alert received from server - ",NULL,0,O);  // received an alert - close connection
            break;
        case STRANGE_EXTENSION:
            logger(fp,(char *)"Strange Extension Detected\n",NULL,0,NULL);
            break;      
        default: break;
        }
    }
}
