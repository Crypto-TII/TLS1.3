// 
// Cryptographic API - this version uses MIRACL core functions
//

#include "tls_crypto_api.h"

// Pull in MIRACL core code

#include "ecdh_NIST256.h"  
#include "ecdh_NIST384.h"
#include "ecdh_C25519.h"
#include "rsa_RSA2048.h"
#include "rsa_RSA4096.h"

csprng RNG;    // Global Crypto Strong RNG - could be a hardware source

// convert TLS octad to MIRACL core octet
static octet octad_to_octet(octad *x)
{
    octet y;
    if (x!=NULL) {
        y.len=x->len;
        y.max=x->max;
        y.val=x->val;
    } else {
        y.len=y.max=0;
        y.val=NULL;
    }
    return y;
}

// Seed the random number generator
void TLS_SEED_RNG(int len, char *r)
{
    RAND_seed(&RNG, len, r);
}

// Return a random byte
int TLS_RANDOM_BYTE()
{
    return RAND_byte(&RNG);
}

// Fill an octad with random values
void TLS_RANDOM_OCTAD(int len,octad *R)
{
    for (int i=0;i<len;i++)
        R->val[i]=TLS_RANDOM_BYTE();
    R->len=len;
}

// create expanded HKDF label LB from label and context
static void hkdfLabel(octad *LB,int length,octad *Label,octad *CTX)
{
    OCT_append_int(LB,length,2);    // 2
    OCT_append_byte(LB,(char)(6+Label->len),1);  // 1
    OCT_append_string(LB,(char *)"tls13 ");   // 6
    OCT_append_octad(LB,Label);  // Label->len
    if (CTX!=NULL)
    {
        OCT_append_byte(LB, (char)(CTX->len), 1); // 1
        OCT_append_octad(LB,CTX);   // CTX->len
    } else {
        OCT_append_byte(LB,0,1);   // 1
    }
}

// HKDF extension for TLS1.3
void TLS_HKDF_Expand_Label(int sha,octad *OKM,int olen,octad *PRK,octad *Label,octad *CTX)
{
    char hl[TLS_MAX_HASH+24];
    octad HL={0,sizeof(hl),hl};

    octet MC_OKM=octad_to_octet(OKM); 
    octet MC_PRK=octad_to_octet(PRK);

    hkdfLabel(&HL,olen,Label,CTX);
    octet MC_HL=octad_to_octet(&HL);
    HKDF_Expand(MC_SHA2,sha,&MC_OKM,olen,&MC_PRK,&MC_HL);
    OKM->len=MC_OKM.len;
    PRK->len=MC_PRK.len;
}

// HKDF - Extract secret from raw input
void TLS_HKDF_Extract(int sha,octad *PRK,octad *SALT,octad *IKM)
{
    octet MC_PRK=octad_to_octet(PRK);   // Make it MIRACL core compatible
    octet MC_SALT=octad_to_octet(SALT);
    octet MC_IKM=octad_to_octet(IKM);

    HKDF_Extract(MC_SHA2,sha,&MC_PRK,&MC_SALT,&MC_IKM);

    IKM->len=MC_IKM.len;              // restore length
    SALT->len=MC_SALT.len;
    PRK->len=MC_PRK.len;
}

// TLS HMAC
void TLS_HMAC(int sha,octad *T,octad *K,octad *M)
{
    octet MC_T=octad_to_octet(T);
    octet MC_K=octad_to_octet(K);
    octet MC_M=octad_to_octet(M);

    HMAC(MC_SHA2,sha,&MC_T,sha,&MC_K,&MC_M);

    T->len=MC_T.len;
    K->len=MC_K.len;
    M->len=MC_M.len;
}

// TLS HASH
void TLS_HASH(int sha,octad *H,octad *M)
{
    octet MC_H=octad_to_octet(H);
    if (M!=NULL)
    {
        octet MC_M=octad_to_octet(M);
        SPhash(MC_SHA2,sha,&MC_H,&MC_M);
    } else {
        SPhash(MC_SHA2,sha,&MC_H,NULL);
    }
    H->len=MC_H.len;
}

// Unified hashing. SHA2 type indicate by hlen. For SHA256 hlen=32 etc
void Hash_Init(int hlen,unihash *h)
{
    if (hlen==TLS_SHA256) 
        HASH256_init(&(h->sh32));
    if (hlen==TLS_SHA384)
        HASH384_init(&(h->sh64));
    if (hlen==TLS_SHA512)
        HASH512_init(&(h->sh64));
    h->hlen=hlen;
}

// Process a byte
void Hash_Process(unihash *h,int b)
{
    if (h->hlen==TLS_SHA256)
        HASH256_process(&(h->sh32),b);
    if (h->hlen==TLS_SHA384)
        HASH384_process(&(h->sh64),b);
    if (h->hlen==TLS_SHA512)
        HASH512_process(&(h->sh64),b);
}

// output digest
void Hash_Output(unihash *h,char *d)
{
    if (h->hlen==TLS_SHA256)
        HASH256_continuing_hash(&(h->sh32),d);
    if (h->hlen==TLS_SHA384)
        HASH384_continuing_hash(&(h->sh64),d);
    if (h->hlen==TLS_SHA512)
        HASH384_continuing_hash(&(h->sh64),d);
}

void AES_GCM_ENCRYPT(crypto *send,int hdrlen,char *hdr,int ptlen,char *pt,octad *TAG)
{ // AES-GCM encryption
    gcm g;
    GCM_init(&g,send->K.len,send->K.val,12,send->IV.val);  // Encrypt with Key and IV
    GCM_add_header(&g,hdr,hdrlen);
    GCM_add_plain(&g,pt,pt,ptlen);
//create and append TA
    GCM_finish(&g,TAG->val); TAG->len=16;
}

void AES_GCM_DECRYPT(crypto *recv,int hdrlen,char *hdr,int ctlen,char *ct,octad *TAG)
{ // AES-GCM decryption
    gcm g;
    GCM_init(&g,recv->K.len,recv->K.val,12,recv->IV.val);  // Decrypt with Key and IV
    GCM_add_header(&g,hdr,hdrlen);
    GCM_add_cipher(&g,ct,ct,ctlen);
//create and append TA
    GCM_finish(&g,TAG->val); TAG->len=16;
}

// generate a public/private key pair in an approved group for a key exchange
void GENERATE_KEY_PAIR(int group,octad *SK,octad *PK)
{
// Random secret key
    TLS_RANDOM_OCTAD(32,SK);

    octet MC_SK=octad_to_octet(SK);
    octet MC_PK=octad_to_octet(PK);
    if (group==X25519)
    {
// RFC 7748
        OCT_reverse(&MC_SK);
        MC_SK.val[32-1]&=248;  
        MC_SK.val[0]&=127;
        MC_SK.val[0]|=64;
        C25519::ECP_KEY_PAIR_GENERATE(NULL, &MC_SK, &MC_PK);
        OCT_reverse(&MC_PK);
    }
    if (group==SECP256R1)
    {
        NIST256::ECP_KEY_PAIR_GENERATE(NULL, &MC_SK, &MC_PK);
    }
    if (group==SECP384R1)
    {
        NIST384::ECP_KEY_PAIR_GENERATE(NULL, &MC_SK, &MC_PK);
    }
    SK->len=MC_SK.len;
    PK->len=MC_PK.len;
}

// generate shared secret SS from secret key SK and public hey PK
void GENERATE_SHARED_SECRET(int group,octad *SK,octad *PK,octad *SS)
{
    octet MC_SK=octad_to_octet(SK);
    octet MC_PK=octad_to_octet(PK);
    octet MC_SS=octad_to_octet(SS);

    if (group==X25519) { // RFC 7748
        OCT_reverse(&MC_PK);
        C25519::ECP_SVDP_DH(&MC_SK, &MC_PK, &MC_SS,0);
        OCT_reverse(&MC_SS);
    }
    if (group==SECP256R1) {
        NIST256::ECP_SVDP_DH(&MC_SK, &MC_PK, &MC_SS,0);
    }
    if (group==SECP384R1) {
        NIST384::ECP_SVDP_DH(&MC_SK, &MC_PK, &MC_SS,0);
    }
    SK->len=MC_SK.len;
    PK->len=MC_PK.len;
    SS->len=MC_SS.len;
}

// RSA 2048-bit PKCS1.5 signature verification
bool RSA_2048_PKCS15_VERIFY(int sha,octad *CERT,octad *SIG,octad *PUBKEY)
{
    bool res;
    char p1[RFS_RSA2048];
    octet P1={0,sizeof(p1),p1};
    char p2[RFS_RSA2048];
    octet P2={0,sizeof(p2),p2};

    octet MC_CERT=octad_to_octet(CERT);
    octet MC_SIG=octad_to_octet(SIG);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    RSA2048::rsa_public_key PK;
    PK.e = 65537; // assuming this!
    RSA2048::RSA_fromOctet(PK.n, &MC_PUBKEY);
    RSA2048::RSA_ENCRYPT(&PK, &MC_SIG, &P2);
    PKCS15(sha, &MC_CERT, &P1);
    res=OCT_comp(&P1, &P2);
    if (!res)
    { // check alternate PKCS1.5 encoding
        PKCS15b(sha, &MC_CERT, &P1);
        res=OCT_comp(&P1, &P2);
    }
    return res;
}

// RSA 4096-bit PKCS1.5 signature verification
bool RSA_4096_PKCS15_VERIFY(int sha,octad *CERT,octad *SIG,octad *PUBKEY)
{
    bool res;
    char p1[RFS_RSA4096];
    octet P1={0,sizeof(p1),p1};
    char p2[RFS_RSA4096];
    octet P2={0,sizeof(p2),p2};

    octet MC_CERT=octad_to_octet(CERT);
    octet MC_SIG=octad_to_octet(SIG);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    RSA4096::rsa_public_key PK;
    PK.e = 65537; // assuming this!
    RSA4096::RSA_fromOctet(PK.n, &MC_PUBKEY);
    RSA4096::RSA_ENCRYPT(&PK, &MC_SIG, &P2);
    PKCS15(sha, &MC_CERT, &P1);
    res=OCT_comp(&P1, &P2);
    if (!res)
    { // check alternate PKCS1.5 encoding
        PKCS15b(sha, &MC_CERT, &P1);
        res=OCT_comp(&P1, &P2);
    }
    return res;
}

// RSA 2048-bit PSS-RSAE signature verification
bool RSA_2048_PSS_RSAE_VERIFY(int sha,octad *MESS,octad *SIG,octad *PUBKEY)
{
    char p[RFS_RSA2048];
    octet P={0,sizeof(p),p};

    octet MC_MESS=octad_to_octet(MESS);
    octet MC_SIG=octad_to_octet(SIG);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    RSA2048::rsa_public_key PK;
    PK.e = 65537;
    RSA2048::RSA_fromOctet(PK.n, &MC_PUBKEY);
    RSA2048::RSA_ENCRYPT(&PK, &MC_SIG, &P);
    if (PSS_VERIFY(sha,&MC_MESS,&P)) 
        return true;
    return false;
}

// RSA 4096-bit PSS-RSAE signature verification
bool RSA_4096_PSS_RSAE_VERIFY(int sha,octad *MESS,octad *SIG,octad *PUBKEY)
{
    char p[RFS_RSA4096];
    octet P={0,sizeof(p),p};

    octet MC_MESS=octad_to_octet(MESS);
    octet MC_SIG=octad_to_octet(SIG);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    RSA4096::rsa_public_key PK;
    PK.e = 65537;
    RSA4096::RSA_fromOctet(PK.n, &MC_PUBKEY);
    RSA4096::RSA_ENCRYPT(&PK, &MC_SIG, &P);
    if (PSS_VERIFY(sha,&MC_MESS,&P)) 
        return true;
    return false;
}

// Curve SECP256R1 elliptic curve ECDSA verification
bool SECP256R1_ECDSA_VERIFY(int sha,octad *CERT,octad *R,octad *S,octad *PUBKEY)
{
    int res;

    octet MC_CERT=octad_to_octet(CERT);
    octet MC_R=octad_to_octet(R);
    octet MC_S=octad_to_octet(S);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    res=NIST256::ECP_PUBLIC_KEY_VALIDATE(&MC_PUBKEY);
    if (res!=0) return false;
    res=NIST256::ECP_VP_DSA(sha, &MC_PUBKEY, &MC_CERT, &MC_R, &MC_S);
    if (res!=0) return false;
    return true;
}

// Curve SECP384R1 elliptic curve ECDSA verification
bool SECP384R1_ECDSA_VERIFY(int sha,octad *CERT,octad *R,octad *S,octad *PUBKEY)
{
    int res;

    octet MC_CERT=octad_to_octet(CERT);
    octet MC_R=octad_to_octet(R);
    octet MC_S=octad_to_octet(S);
    octet MC_PUBKEY=octad_to_octet(PUBKEY);

    res=NIST384::ECP_PUBLIC_KEY_VALIDATE(&MC_PUBKEY);
    if (res!=0) return false;
    res=NIST384::ECP_VP_DSA(sha, &MC_PUBKEY, &MC_CERT, &MC_R, &MC_S);
    if (res!=0) return false;
    return true;
}

// Use Curve SECP256R1 ECDSA to digitally sign a message using a private key 
void SECP256R1_ECDSA_SIGN(int sha,octad *KEY,octad *MESS,octad *R,octad *S)
{
    octet MC_MESS=octad_to_octet(MESS);
    octet MC_KEY=octad_to_octet(KEY);
    octet MC_R=octad_to_octet(R);
    octet MC_S=octad_to_octet(S);

    NIST256::ECP_SP_DSA(sha, &RNG, NULL, &MC_KEY, &MC_MESS, &MC_R, &MC_S);

    R->len=MC_R.len;
    S->len=MC_S.len;
}

// Use Curve SECP384R1 ECDSA to digitally sign a message using a private key 
void SECP384R1_ECDSA_SIGN(int sha,octad *KEY,octad *MESS,octad *R,octad *S)
{
    octet MC_MESS=octad_to_octet(MESS);
    octet MC_KEY=octad_to_octet(KEY);
    octet MC_R=octad_to_octet(R);
    octet MC_S=octad_to_octet(S);

    NIST256::ECP_SP_DSA(sha, &RNG, NULL, &MC_KEY, &MC_MESS, &MC_R, &MC_S);

    R->len=MC_R.len;
    S->len=MC_S.len;
}

// Use RSA-2048 PSS-RSAE to digitally sign a message using a private key
void RSA_2048_PSS_RSAE_SIGN(int sha,octad *KEY,octad *MESS,octad *SIG)
{
    int len=KEY->len/5;   // length of p and q
    if (len!=128) return;
    char p[128];
    octet P={len,sizeof(p),p};
    char q[128];
    octet Q={len,sizeof(q),q};
    char dp[128];
    octet DP={len,sizeof(dp),dp};
    char dq[128];
    octet DQ={len,sizeof(dq),dq};
    char c[128];
    octet C={len,sizeof(c),c}; 
    for (int i=0;i<len;i++)
    {
        p[i]=KEY->val[i];
        q[i]=KEY->val[i+len];
        dp[i]=KEY->val[i+2*len];
        dq[i]=KEY->val[i+3*len];
        c[i]=KEY->val[i+4*len];
    }
    RSA2048::rsa_private_key SK;
    char enc[256];
    octet ENC={0,sizeof(enc),enc};
    RSA2048::RSA_PRIVATE_KEY_FROM_OPENSSL(&P,&Q,&DP,&DQ,&C,&SK);

    octet MC_MESS=octad_to_octet(MESS);
    octet MC_SIG=octad_to_octet(SIG);

    PSS_ENCODE(sha, &MC_MESS, &RNG, &ENC);
    RSA2048::RSA_DECRYPT(&SK,&ENC,&MC_SIG);
    SIG->len=MC_SIG.len;
}

// Use RSA-4096 PSS-RSAE to digitally sign a message using a private key
void RSA_4096_PSS_RSAE_SIGN(int sha,octad *KEY,octad *MESS,octad *SIG)
{
    int len=KEY->len/5;   // length of p and q
    if (len!=256) return;
    char p[256];
    octet P={len,sizeof(p),p};
    char q[256];
    octet Q={len,sizeof(q),q};
    char dp[256];
    octet DP={len,sizeof(dp),dp};
    char dq[256];
    octet DQ={len,sizeof(dq),dq};
    char c[256];
    octet C={len,sizeof(c),c}; 
    for (int i=0;i<len;i++)
    {
        p[i]=KEY->val[i];
        q[i]=KEY->val[i+len];
        dp[i]=KEY->val[i+2*len];
        dq[i]=KEY->val[i+3*len];
        c[i]=KEY->val[i+4*len];
    }
    RSA4096::rsa_private_key SK;
    char enc[512];
    octet ENC={0,sizeof(enc),enc};

    octet MC_MESS=octad_to_octet(MESS);
    octet MC_SIG=octad_to_octet(SIG);

    RSA4096::RSA_PRIVATE_KEY_FROM_OPENSSL(&P,&Q,&DP,&DQ,&C,&SK);
    PSS_ENCODE(sha, &MC_MESS, &RNG, &ENC);
    RSA4096::RSA_DECRYPT(&SK,&ENC,&MC_SIG);
    SIG->len=MC_SIG.len;
}
