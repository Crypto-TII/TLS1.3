// 
// Process input recieved from Server
//
#include "tls_client_send.h"

// Build Pre-Shared Key Share Extension
void addPresharedKeyExt(octet *EXT,octet *TICK,unsign32 obf_age,octet* BD)
{
    int len=4+TICK->len+BD->len;
    char psk[1024];
    octet PSK={0,sizeof(psk),psk};
    OCT_jint(&PSK,PRESHARED_KEY,2);

}

// Build Servername Extension
void addServerNameExt(octet *EXT,char *servername)
{
    int len=strlen(servername);
    char sn[TLS_MAX_SERVER_NAME+9];
    octet SN = {0, sizeof(sn), sn};
    OCT_jint(&SN,SERVER_NAME,2);  // This extension is SERVER_NAME(0)
    OCT_jint(&SN,5+len,2);   // In theory its a list..
    OCT_jint(&SN,3+len,2);   // but only one entry
    OCT_jint(&SN,0,1);     // Server is of type DNS Hostname (only one type supported, and only one of each type)
    OCT_jint(&SN,len,2);   // serverName length
    OCT_jstring(&SN,servername); // servername
    OCT_joctet(EXT,&SN);
}
    
// Build Supported Groups Extension
void addSupportedGroupsExt(octet *EXT,int nsg,int *supportedGroups)
{
    char sg[6+TLS_MAX_SUPPORTED_GROUPS*2];
    octet SG = {0, sizeof(sg), sg};
    OCT_jint(&SG,SUPPORTED_GROUPS,2); // This extension is SUPPORTED GROUPS(0x0a)
    OCT_jint(&SG,2*nsg+2,2);          // Total length
    OCT_jint(&SG,2*nsg,2);            // Number of entries
    for (int i=0;i<nsg;i++)          // One entry per supported group 
        OCT_jint(&SG,supportedGroups[i],2);
    OCT_joctet(EXT,&SG);
}

// Build Signature algorithms Extension
void addSigAlgsExt(octet *EXT,int nsa,int *sigAlgs)
{
    char sa[6+TLS_MAX_SUPPORTED_SIGS*2];
    octet SA={0,sizeof(sa),sa};
    OCT_jint(&SA,SIG_ALGS,2);  // This extension is SIGNATURE_ALGORITHMS(0x0d)
    OCT_jint(&SA,2*nsa+2,2);   // Total length
    OCT_jint(&SA,2*nsa,2);     // Number of entries
    for (int i=0;i<nsa;i++)   // One entry per supported signature algorithm
        OCT_jint(&SA,sigAlgs[i],2);
    OCT_joctet(EXT,&SA);
}

// Add Client Key Share extension
// Offer a choice of publics keys (some may be PQ!)
void addKeyShareExt(octet *EXT,int nalgs,int alg[],octet PK[])
{
    char ks[6+TLS_MAX_KEY_SHARES*(4+TLS_MAX_PUB_KEY_SIZE)];
    octet KS={0,sizeof(ks),ks};
    int tlen=0;
    for (int i=0;i<nalgs;i++)
    {
        tlen+=4;
        tlen+=PK[i].len;
    }
    OCT_jint(&KS,KEY_SHARE,2); // This extension is KEY_SHARE(0x33)
    OCT_jint(&KS,tlen+2,2);
    OCT_jint(&KS,tlen,2);
    for (int i=0;i<nalgs;i++)
    {
        OCT_jint(&KS,alg[i],2);
        OCT_jint(&KS,PK[i].len,2);
        OCT_joctet(&KS,&PK[i]);
    }
    OCT_joctet(EXT,&KS);
}

void addPSKExt(octet *EXT,int mode)
{
    char ps[6];
    octet PS={0,sizeof(ps),ps};
    OCT_jint(&PS,PSK_MODE,2);
    OCT_jint(&PS,2,2);
    OCT_jint(&PS,1,1);
    OCT_jint(&PS,mode,1);
    OCT_joctet(EXT,&PS);
}

void addVersionExt(octet *EXT,int version)
{
    char vs[7];
    octet VS={0,sizeof(vs),vs};
    OCT_jint(&VS,TLS_VER,2);
    OCT_jint(&VS,3,2);
    OCT_jint(&VS,2,1);
    OCT_jint(&VS,version,2);
    OCT_joctet(EXT,&VS);
}

void addCookieExt(octet *EXT,octet *CK)
{
    OCT_jint(EXT,COOKIE,2);
    OCT_jint(EXT,CK->len,2);
    OCT_joctet(EXT,CK);
}

// Create 32-byte random octet
int clientRandom(octet *RN,csprng *RNG)
{
    OCT_rand(RN,RNG,32);
    return 32;
}

// Create random 32-byte session ID (not used in TLS1.3)
int sessionID(octet *SI,csprng *RNG)
{
    OCT_rand(SI,RNG,32);
    return 1+SI->len;
}

// build cipher-suites octet
int cipherSuites(octet *CS,int ncs,int *ciphers)
{
    OCT_clear(CS);
    OCT_jint(CS,2*ncs,2);
    for (int i=0;i<ncs;i++)
        OCT_jint(CS,ciphers[i],2);
    return CS->len;
}

// Send a client message CM (in a single record). AEAD encrypted if K!=NULL
// recno is count of records sent with this key/IV combo
void sendClientMessage(int sock,int rectype,int version,octet *K,octet *OIV,unsign32 &recno,octet *CM)
{
    int reclen;
    char record[TLS_MAX_CLIENT_RECORD];
    octet RECORD={0,sizeof(record),record};
    char tag[TLS_TAG_SIZE];
    octet TAG={0,sizeof(tag),tag};
    char iv[TLS_IV_SIZE];
    octet IV={0,sizeof(iv),iv};

    if (K==NULL)
    { // no encryption
        OCT_jbyte(&RECORD,rectype,1);
        OCT_jint(&RECORD,version,2);
        reclen=CM->len;
        OCT_jint(&RECORD,reclen,2);
        OCT_joctet(&RECORD,CM); // CM->len
    } else { // encrypted, and sent as application record
        OCT_jbyte(&RECORD,APPLICATION,1);
        OCT_jint(&RECORD,TLS1_2,2);
        reclen=CM->len+16+1;       // 16 for the TAG, 1 for the record type
        OCT_jint(&RECORD,reclen,2);
        OCT_joctet(&RECORD,CM); 
        OCT_jbyte(&RECORD,rectype,1); // append and encrypt actual record type
// could add random padding after this

// AES-GCM
        recno=updateIV(&IV,OIV,recno); // update record number
        gcm g;
        GCM_init(&g,K->len,K->val,12,IV.val);  // Encrypt with Client Application Key and IV
        GCM_add_header(&g,RECORD.val,5);
        GCM_add_plain(&g,&RECORD.val[5],&RECORD.val[5],reclen-16);
//create and append TAG
        GCM_finish(&g,TAG.val); TAG.len=16;
        OCT_joctet(&RECORD,&TAG);
    }
printf("Client to Server -> "); OCT_output(&RECORD);
    sendOctet(sock,&RECORD);
}

// build and transmit client hello. Append pre-prepared extensions
void sendClientHello(int sock,int version,octet *CH,int nsc,int *ciphers,csprng *RNG,octet *CID,octet *EXTENSIONS)
{
    char rn[32];
    octet RN = {0, sizeof(rn), rn};
    char cs[2+TLS_MAX_CIPHER_SUITES*2];
    octet CS = {0, sizeof(cs), cs};
    int compressionMethods=0x0100;
    int total=8;
    int extlen=EXTENSIONS->len;
    total+=clientRandom(&RN,RNG);
    total+=sessionID(CID,RNG);
    total+=cipherSuites(&CS,nsc,ciphers);

    OCT_clear(CH);
    OCT_jbyte(CH,CLIENT_HELLO,1);  // clientHello handshake message  // 1
    OCT_jint(CH,total+extlen-2,3);   // 3

    OCT_jint(CH,TLS1_2,2);              // 2
    OCT_joctet(CH,&RN);              // 32
    OCT_jbyte(CH,CID->len,1);        // 1   
    OCT_joctet(CH,CID);              // 32
    OCT_joctet(CH,&CS);             // 2+TLS_MAX_CIPHER_SUITES*2
    OCT_jint(CH,compressionMethods,2);  // 2

    OCT_jint(CH,extlen,2);            // 2
    OCT_joctet(CH,EXTENSIONS);

// transmit it
    unsign32 nulrec=0;
    sendClientMessage(sock,HSHAKE,version,NULL,NULL,nulrec,CH);
}

// send client alert - might be encrypted if K!=NULL
void sendClientAlert(int sock,int type,octet *K,octet *OIV,unsign32 &recno)
{
    char pt[2];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,0x02,1);  // alerts are always fatal
    OCT_jbyte(&PT,type,1);

    sendClientMessage(sock,ALERT,TLS1_2,K,OIV,recno,&PT);
}

// Send final client handshake verification data
void sendClientVerify(int sock,octet *K,octet *OIV,unsign32 &recno,octet *CHF)
{
    char pt[TLS_MAX_HASH+4];
    octet PT={0,sizeof(pt),pt};

    OCT_jbyte(&PT,FINISHED,1);  // indicates handshake message "client finished" 1
    OCT_jint(&PT,CHF->len,3); // .. and its length  3
    OCT_joctet(&PT,CHF);

    sendClientMessage(sock,HSHAKE,TLS1_2,K,OIV,recno,&PT);
}


