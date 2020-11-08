
// extract traffic, handshake and application keys from raw secrets
#include "tls_keys_calc.h"

// create expanded HKDF label LB from label and context
static void hkdfLabel(octet *LB,int length,octet *Label,octet *CTX)
{
    OCT_jint(LB,length,2);
    OCT_jbyte(LB,(char)(6+Label->len),1);
    OCT_jstring(LB,(char *)"tls13 ");
    OCT_joctet(LB,Label);
    if (CTX!=NULL)
    {
        OCT_jbyte(LB, (char)(CTX->len), 1);
        OCT_joctet(LB,CTX);
    } else {
        OCT_jbyte(LB,0,1);
    }
}

// HKDF extension for TLS1.3
static void HKDF_Expand_Label(int hash,int hlen,octet *OKM,int olen,octet *PRK,octet *Label,octet *CTX)
{
    char hl[200];
    octet HL={0,sizeof(hl),hl};
    hkdfLabel(&HL,olen,Label,CTX);
    HKDF_Expand(hash,hlen,OKM,olen,PRK,&HL);
}

bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H)
{
    char fk[32];
    octet FK = {0,sizeof(fk),fk};
    char vd[32];
    octet VD = {0,sizeof(vd),vd};
    char info[12];
    octet INFO = {0,sizeof(info),info};
    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"finished");
    HKDF_Expand_Label(MC_SHA2,sha,&FK,32,SHTS,&INFO,NULL); 

    HMAC(MC_SHA2,sha,&VD,sha,&FK,H);
//    printf("VD=            ");OCT_output(&VD);
    return OCT_comp(SF,&VD);
}

// Extract Client and Server Application keys and IVs from Transcript Hash, Handshake secret, 
void GET_APPLICATION_SECRETS(int sha,octet *CAK,octet *CAIV,octet *SAK,octet *SAIV,octet *H,octet *HS)
{
    char cts[64];
    octet CTS = {0,sizeof(cts),cts};
    char sts[64];
    octet STS = {0,sizeof(sts),sts};
    char ds[64];
    octet DS = {0,sizeof(ds),ds};
    char ms[64];
    octet MS = {0,sizeof(ms),ms};
    char emh[64];
    octet EMH = {0,sizeof(emh),emh};
    char zk[32];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[32];
    octet INFO = {0,sizeof(info),info};
    OCT_jbyte(&ZK,0,32);
    SPhash(MC_SHA2,sha,&EMH,NULL);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,32,HS,&INFO,&EMH);   // Use handshake secret from above
    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,&MS,&DS,&ZK);
    printf("Master Secret= ");OCT_output(&MS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,&CTS,32,&MS,&INFO,H);

    printf("Client application traffic secret= ");OCT_output(&CTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,&STS,32,&MS,&INFO,H);

    printf("Server application traffic secret= ");OCT_output(&STS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CAK,16,&CTS,&INFO,NULL);

    printf("Client application key= "); OCT_output(CAK);

    HKDF_Expand_Label(MC_SHA2,sha,SAK,16,&STS,&INFO,NULL);

    printf("Server application key= "); OCT_output(SAK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CAIV,12,&CTS,&INFO,NULL);

    printf("Client application IV= "); OCT_output(CAIV);

    HKDF_Expand_Label(MC_SHA2,sha,SAIV,12,&STS,&INFO,NULL);

    printf("Server application IV= "); OCT_output(SAIV);
}

// Extract Handshake secret, Client and Server Handshake keys and IVs, and CLient and Server Handshake Traffic keys from Transcript Hash and Shared secret
void GET_HANDSHAKE_SECRETS(int sha,octet *HS,octet *CHK,octet *CHIV,octet *SHK,octet *SHIV, octet *CHTS,octet *SHTS,  octet *H,octet *SS)
{
/*    char cts[64];
    octet CTS = {0,sizeof(cts),cts};
    char sts[64];
    octet STS = {0,sizeof(sts),sts}; */
    char es[64];
    octet ES = {0,sizeof(es),es};
    char ds[64];
    octet DS = {0,sizeof(ds),ds};
    char emh[64];
    octet EMH = {0,sizeof(emh),emh};
    char zk[32];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[32];
    octet INFO = {0,sizeof(info),info};
    OCT_jbyte(&ZK,0,32);
    SPhash(MC_SHA2,sha,&EMH,NULL);


    HKDF_Extract(MC_SHA2,sha,&ES,&ZK,&ZK);

    printf("Early Secret = "); OCT_output(&ES);
    printf("Empty Hash context = "); OCT_output(&EMH);
    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,32,&ES,&INFO,&EMH);

    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,HS,&DS,SS);

    printf("Handshake Secret= ");OCT_output(HS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CHTS,32,HS,&INFO,H);

    printf("Client handshake traffic secret= ");OCT_output(CHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,SHTS,32,HS,&INFO,H);

    printf("Server handshake traffic secret= ");OCT_output(SHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CHK,16,CHTS,&INFO,NULL);

    printf("Client handshake key= "); OCT_output(CHK);

    HKDF_Expand_Label(MC_SHA2,sha,SHK,16,SHTS,&INFO,NULL);

    printf("Server handshake key= "); OCT_output(SHK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CHIV,12,CHTS,&INFO,NULL);

    printf("Client handshake IV= "); OCT_output(CHIV);

    HKDF_Expand_Label(MC_SHA2,sha,SHIV,12,SHTS,&INFO,NULL);

    printf("Server handshake IV= "); OCT_output(SHIV);
}