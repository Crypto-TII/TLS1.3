// 
// Cryptographic API
//
#include "tls_crypto_api.h"

using namespace core;

// Unified hashing. SHA2 type indicate by hlen. For SHA256 hlen=32 etc
void Hash_Init(int hlen,unihash *h)
{
    if (hlen==32) 
        HASH256_init(&(h->sh32));
    if (hlen==48)
        HASH384_init(&(h->sh64));
    if (hlen==64)
        HASH512_init(&(h->sh64));
    h->hlen=hlen;
}

// Process a byte
void Hash_Process(unihash *h,int b)
{
    if (h->hlen==32)
        HASH256_process(&(h->sh32),b);
    if (h->hlen==48)
        HASH384_process(&(h->sh64),b);
    if (h->hlen==64)
        HASH512_process(&(h->sh64),b);
}

// output digest
void Hash_Output(unihash *h,char *d)
{
    if (h->hlen==32)
        HASH256_continuing_hash(&(h->sh32),d);
    if (h->hlen==48)
        HASH384_continuing_hash(&(h->sh64),d);
    if (h->hlen==64)
        HASH384_continuing_hash(&(h->sh64),d);
}

void AES_GCM_ENCRYPT(crypto *send,int hdrlen,char *hdr,int ptlen,char *pt,octet *TAG)
{ // AES-GCM encryption
    gcm g;
    GCM_init(&g,send->K.len,send->K.val,12,send->IV.val);  // Encrypt with Key and IV
    GCM_add_header(&g,hdr,hdrlen);
    GCM_add_plain(&g,pt,pt,ptlen);
//create and append TA
    GCM_finish(&g,TAG->val); TAG->len=16;
}

void AES_GCM_DECRYPT(crypto *recv,int hdrlen,char *hdr,int ctlen,char *ct,octet *TAG)
{ // AES-GCM decryption
    gcm g;
    GCM_init(&g,recv->K.len,recv->K.val,12,recv->IV.val);  // Decrypt with Key and IV
    GCM_add_header(&g,hdr,hdrlen);
    GCM_add_cipher(&g,ct,ct,ctlen);
//create and append TA
    GCM_finish(&g,TAG->val); TAG->len=16;
}

// generate a public/private key pair in an approved group for a key exchange
void GENERATE_KEY_PAIR(csprng *RNG,int group,octet *SK,octet *PK)
{
    int sklen=32;
    if (group==SECP384R1)
        sklen=48;
// Random secret key
    OCT_rand(SK,RNG,32);
    if (group==X25519)
    {
// RFC 7748
        OCT_reverse(SK);
        SK->val[32-1]&=248;  
        SK->val[0]&=127;
        SK->val[0]|=64;
        C25519::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
        OCT_reverse(PK);
    }
    if (group==SECP256R1)
    {
        NIST256::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
    }
    if (group==SECP384R1)
    {
        NIST384::ECP_KEY_PAIR_GENERATE(NULL, SK, PK);
    }
}

// generate shared secret SS from secret key SK and public hey PK
void GENERATE_SHARED_SECRET(int group,octet *SK,octet *PK,octet *SS)
{
    if (group==X25519) { // RFC 7748
        OCT_reverse(PK);
        C25519::ECP_SVDP_DH(SK, PK, SS,0);
        OCT_reverse(SS);
    }
    if (group==SECP256R1) {
        NIST256::ECP_SVDP_DH(SK, PK, SS,0);
    }
    if (group==SECP384R1) {
        NIST384::ECP_SVDP_DH(SK, PK, SS,0);
    }
}

// RSA 2048-bit PKCS1.5 signature verification
bool RSA_2048_PKCS15_VERIFY(int sha,octet *CERT,octet *SIG,octet *PUBKEY)
{
    bool res;
    char p1[RFS_RSA2048];
    octet P1={0,sizeof(p1),p1};
    char p2[RFS_RSA2048];
    octet P2={0,sizeof(p2),p2};
    RSA2048::rsa_public_key PK;
    PK.e = 65537; // assuming this!
    RSA2048::RSA_fromOctet(PK.n, PUBKEY);
    RSA2048::RSA_ENCRYPT(&PK, SIG, &P2);
    PKCS15(sha, CERT, &P1);
    res=OCT_comp(&P1, &P2);
    if (!res)
    { // check alternate PKCS1.5 encoding
        PKCS15b(sha, CERT, &P1);
        res=OCT_comp(&P1, &P2);
    }
    return res;
}

// RSA 4096-bit PKCS1.5 signature verification
bool RSA_4096_PKCS15_VERIFY(int sha,octet *CERT,octet *SIG,octet *PUBKEY)
{
    bool res;
    char p1[RFS_RSA4096];
    octet P1={0,sizeof(p1),p1};
    char p2[RFS_RSA4096];
    octet P2={0,sizeof(p2),p2};
    RSA4096::rsa_public_key PK;
    PK.e = 65537; // assuming this!
    RSA4096::RSA_fromOctet(PK.n, PUBKEY);
    RSA4096::RSA_ENCRYPT(&PK, SIG, &P2);
    PKCS15(sha, CERT, &P1);
    res=OCT_comp(&P1, &P2);
    if (!res)
    { // check alternate PKCS1.5 encoding
        PKCS15b(sha, CERT, &P1);
        res=OCT_comp(&P1, &P2);
    }
    return res;
}

// RSA 2048-bit PSS-RSAE signature verification
bool RSA_2048_PSS_RSAE_VERIFY(int sha,octet *MESS,octet *SIG,octet *PUBKEY)
{
    char p[RFS_RSA2048];
    octet P={0,sizeof(p),p};
    RSA2048::rsa_public_key PK;
    PK.e = 65537;
    RSA2048::RSA_fromOctet(PK.n, PUBKEY);
    RSA2048::RSA_ENCRYPT(&PK, SIG, &P);
    if (PSS_VERIFY(sha,MESS,&P)) 
        return true;
    return false;
}

// RSA 4096-bit PSS-RSAE signature verification
bool RSA_4096_PSS_RSAE_VERIFY(int sha,octet *MESS,octet *SIG,octet *PUBKEY)
{
    bool res;
    char p[RFS_RSA4096];
    octet P={0,sizeof(p),p};
    RSA4096::rsa_public_key PK;
    PK.e = 65537;
    RSA4096::RSA_fromOctet(PK.n, PUBKEY);
    RSA4096::RSA_ENCRYPT(&PK, SIG, &P);
    if (PSS_VERIFY(sha,MESS,&P)) 
        return true;
    return false;
}

// Curve SECP256R1 elliptic curve ECDSA verification
bool SECP256R1_ECDSA_VERIFY(int sha,octet *CERT,octet *R,octet *S,octet *PUBKEY)
{
    int res;
    res=NIST256::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
    if (res!=0) return false;
    res=NIST256::ECP_VP_DSA(sha, PUBKEY, CERT, R, S);
    if (res!=0) return false;
    return true;
}

// Curve SECP384R1 elliptic curve ECDSA verification
bool SECP384R1_ECDSA_VERIFY(int sha,octet *CERT,octet *R,octet *S,octet *PUBKEY)
{
    int res;
    res=NIST384::ECP_PUBLIC_KEY_VALIDATE(PUBKEY);
    if (res!=0) return false;
    res=NIST384::ECP_VP_DSA(sha, PUBKEY, CERT, R, S);
    if (res!=0) return false;
    return true;
}

// Use Curve SECP256R1 ECDSA to digitally sign a message using a private key 
void SECP256R1_ECDSA_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *R,octet *S)
{
    NIST256::ECP_SP_DSA(sha,RNG, NULL, KEY, MESS, R, S);
}

// Use Curve SECP384R1 ECDSA to digitally sign a message using a private key 
void SECP384R1_ECDSA_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *R,octet *S)
{
    NIST256::ECP_SP_DSA(sha,RNG, NULL, KEY, MESS, R, S);
}

// Use RSA-2048 PSS-RSAE to digitally sign a message using a private key
void RSA_2048_PSS_RSAE_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *SIG)
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
    PSS_ENCODE(sha, MESS, RNG, &ENC);
    RSA2048::RSA_DECRYPT(&SK,&ENC,SIG);
}

// Use RSA-4096 PSS-RSAE to digitally sign a message using a private key
void RSA_4096_PSS_RSAE_SIGN(int sha,csprng *RNG,octet *KEY,octet *MESS,octet *SIG)
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
    RSA4096::RSA_PRIVATE_KEY_FROM_OPENSSL(&P,&Q,&DP,&DQ,&C,&SK);
    PSS_ENCODE(sha, MESS, RNG, &ENC);
    RSA4096::RSA_DECRYPT(&SK,&ENC,SIG);
}
