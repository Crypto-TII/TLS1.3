
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

// create verification data
void VERIFY_DATA(int sha,octet *CF,octet *CHTS,octet *H)
{
    char fk[64];
    octet FK = {0,sizeof(fk),fk};
    char info[12];
    octet INFO = {0,sizeof(info),info};
    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"finished");
    HKDF_Expand_Label(MC_SHA2,sha,&FK,sha,CHTS,&INFO,NULL); 

    HMAC(MC_SHA2,sha,CF,sha,&FK,H);
}

// check verification data
bool IS_VERIFY_DATA(int sha,octet *SF,octet *SHTS,octet *H)
{
    char vd[64];
    octet VD = {0,sizeof(vd),vd};
    VERIFY_DATA(sha,&VD,SHTS,H);
    return OCT_comp(SF,&VD);
}

// Extract Client and Server Application keys and IVs from Transcript Hash, Handshake secret, 
void GET_APPLICATION_SECRETS(int cipher_suite,octet *CAK,octet *CAIV,octet *SAK,octet *SAIV,octet *H,octet *HS)
{
    int sha,key;
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
    char zk[64];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[32];
    octet INFO = {0,sizeof(info),info};

    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=32;
        key=16;
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=48;
        key=32;
    }

    OCT_jbyte(&ZK,0,sha);
    SPhash(MC_SHA2,sha,&EMH,NULL);  // 

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,HS,&INFO,&EMH);   // Use handshake secret from above
//    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,&MS,&DS,&ZK);
//    printf("Master Secret= ");OCT_output(&MS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,&CTS,sha,&MS,&INFO,H);

    printf("Client application traffic secret= ");OCT_output(&CTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s ap traffic");
    HKDF_Expand_Label(MC_SHA2,sha,&STS,sha,&MS,&INFO,H);

    printf("Server application traffic secret= ");OCT_output(&STS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CAK,key,&CTS,&INFO,NULL);

    printf("Client application key= "); OCT_output(CAK);

    HKDF_Expand_Label(MC_SHA2,sha,SAK,key,&STS,&INFO,NULL);

    printf("Server application key= "); OCT_output(SAK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CAIV,12,&CTS,&INFO,NULL);

    printf("Client application IV= "); OCT_output(CAIV);

    HKDF_Expand_Label(MC_SHA2,sha,SAIV,12,&STS,&INFO,NULL);

    printf("Server application IV= "); OCT_output(SAIV);
}

// Extract Handshake secret, Client and Server Handshake keys and IVs, and Client and Server Handshake Traffic keys from Transcript Hash and Shared secret
void GET_HANDSHAKE_SECRETS(int cipher_suite,octet *HS,octet *CHK,octet *CHIV,octet *SHK,octet *SHIV, octet *CHTS,octet *SHTS,  octet *H,octet *SS)
{
    int sha,key;
    char es[64];
    octet ES = {0,sizeof(es),es};
    char ds[64];
    octet DS = {0,sizeof(ds),ds};
    char emh[64];
    octet EMH = {0,sizeof(emh),emh};
    char zk[64];                    // Zero Key
    octet ZK = {0,sizeof(zk),zk};
    char info[32];
    octet INFO = {0,sizeof(info),info};

    if (cipher_suite==TLS_AES_128_GCM_SHA256)
    {
        sha=32;
        key=16;
    }
    if (cipher_suite==TLS_AES_256_GCM_SHA384)
    {
        sha=48;
        key=32;
    }

    OCT_jbyte(&ZK,0,sha);
    SPhash(MC_SHA2,sha,&EMH,NULL);  // hash of ""

    HKDF_Extract(MC_SHA2,sha,&ES,&ZK,&ZK);  // hash function, ES is output, ZK is salt and IKM

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"derived");
    HKDF_Expand_Label(MC_SHA2,sha,&DS,sha,&ES,&INFO,&EMH);

//    printf("Derived Secret = "); OCT_output(&DS);

    HKDF_Extract(MC_SHA2,sha,HS,&DS,SS);

    printf("Handshake Secret= ");OCT_output(HS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"c hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,CHTS,sha,HS,&INFO,H);

    printf("Client handshake traffic secret= ");OCT_output(CHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"s hs traffic");
    HKDF_Expand_Label(MC_SHA2,sha,SHTS,sha,HS,&INFO,H);

    printf("Server handshake traffic secret= ");OCT_output(SHTS);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"key");
    HKDF_Expand_Label(MC_SHA2,sha,CHK,key,CHTS,&INFO,NULL);

    printf("Client handshake key= "); OCT_output(CHK);

    HKDF_Expand_Label(MC_SHA2,sha,SHK,key,SHTS,&INFO,NULL);

    printf("Server handshake key= "); OCT_output(SHK);

    OCT_clear(&INFO);
    OCT_jstring(&INFO,(char *)"iv");
    HKDF_Expand_Label(MC_SHA2,sha,CHIV,12,CHTS,&INFO,NULL);

    printf("Client handshake IV= "); OCT_output(CHIV);

    HKDF_Expand_Label(MC_SHA2,sha,SHIV,12,SHTS,&INFO,NULL);

    printf("Server handshake IV= "); OCT_output(SHIV);

}