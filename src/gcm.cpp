/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Implementation of the AES-GCM Encryption/Authentication
 *
 * Some restrictions..
 * 1. Only for use with AES
 * 2. Returned tag is always 128-bits. Truncate at your own risk.
 * 3. The order of function calls must follow some rules
 *
 * Typical sequence of calls..
 * 1. call GCM_init
 * 2. call GCM_add_header any number of times, as long as length of header is multiple of 16 bytes (block size)
 * 3. call GCM_add_header one last time with any length of header
 * 4. call GCM_add_cipher any number of times, as long as length of cipher/plaintext is multiple of 16 bytes
 * 5. call GCM_add_cipher one last time with any length of cipher/plaintext
 * 6. call GCM_finish to extract the tag.
 *
 * See http://www.mindspring.com/~dmcgrew/gcm-nist-6.pdf
 */
/* SU=m, m is Stack Usage */

#include <stdlib.h>
#include <string.h>
#include "arch.h"
#include "core.h"

using namespace core;

#define NB 4
#define MR_TOBYTE(x) ((uchar)((x)))

static unsign32 pack(const uchar *b)
{
    /* pack bytes into a 32-bit Word */
    return ((unsign32)b[0] << 24) | ((unsign32)b[1] << 16) | ((unsign32)b[2] << 8) | (unsign32)b[3];
}

static void unpack(unsign32 a, uchar *b)
{
    /* unpack bytes from a word */
    b[3] = MR_TOBYTE(a);
    b[2] = MR_TOBYTE(a >> 8);
    b[1] = MR_TOBYTE(a >> 16);
    b[0] = MR_TOBYTE(a >> 24);
}

static void precompute(gcm *g, uchar *H)
{
    /* precompute small 2k bytes gf2m table of x^n.H */
    int i, j;
    unsign32 *last, *next, b;

    for (i = j = 0; i < NB; i++, j += 4) g->table[0][i] = pack((uchar *)&H[j]);

    for (i = 1; i < 128; i++)
    {
        next = g->table[i];
        last = g->table[i - 1];
        b = 0;
        for (j = 0; j < NB; j++)
        {
            next[j] = b | (last[j]) >> 1;
            b = last[j] << 31;
        }
        if (b) next[0] ^= 0xE1000000; /* irreducible polynomial */
    }
}

/* SU= 32 */
static void gf2mul(gcm *g)
{
    /* gf2m mul - Z=H*X mod 2^128 */
    int i, j, m, k;
    unsign32 P[4];
    unsign32 b;

    P[0] = P[1] = P[2] = P[3] = 0;
    j = 8;
    m = 0;
    for (i = 0; i < 128; i++)
    {
        b = (unsign32)(g->stateX[m] >> (--j)) & 1;
        b = ~b + 1;
        for (k = 0; k < NB; k++) P[k] ^= (g->table[i][k] & b);
        if (j == 0)
        {
            j = 8;
            m++;
            if (m == 16) break;
        }
    }
    for (i = j = 0; i < NB; i++, j += 4) unpack(P[i], (uchar *)&g->stateX[j]);
}

/* SU= 32 */
static void GCM_wrap(gcm *g)
{
    /* Finish off GHASH */
    int i, j;
    unsign32 F[4];
    uchar L[16];

    /* convert lengths from bytes to bits */
    F[0] = (g->lenA[0] << 3) | (g->lenA[1] & 0xE0000000) >> 29;
    F[1] = g->lenA[1] << 3;
    F[2] = (g->lenC[0] << 3) | (g->lenC[1] & 0xE0000000) >> 29;
    F[3] = g->lenC[1] << 3;
    for (i = j = 0; i < NB; i++, j += 4) unpack(F[i], (uchar *)&L[j]);

    for (i = 0; i < 16; i++) g->stateX[i] ^= L[i];
    gf2mul(g);
}

static int GCM_ghash(gcm *g, char *plain, int len)
{
    int i, j = 0;
    if (g->status == GCM_ACCEPTING_HEADER) g->status = GCM_ACCEPTING_CIPHER;
    if (g->status != GCM_ACCEPTING_CIPHER) return 0;

    while (j < len)
    {
        for (i = 0; i < 16 && j < len; i++)
        {
            g->stateX[i] ^= plain[j++];
            g->lenC[1]++;
            if (g->lenC[1] == 0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len % 16 != 0) g->status = GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 48 */
/* Initialize GCM mode */
void core::GCM_init(gcm* g, int nk, char *key, int niv, char *iv)
{
    /* iv size niv is usually 12 bytes (96 bits). AES key size nk can be 16,24 or 32 bytes */
    int i;
    uchar H[16];
    for (i = 0; i < 16; i++)
    {
        H[i] = 0;
        g->stateX[i] = 0;
    }

    AES_init(&(g->a), ECB, nk, key, iv);
    AES_ecb_encrypt(&(g->a), H);    /* E(K,0) */
    precompute(g, H);

    g->lenA[0] = g->lenC[0] = g->lenA[1] = g->lenC[1] = 0;
    if (niv == 12)
    {
        for (i = 0; i < 12; i++) g->a.f[i] = iv[i];
        unpack((unsign32)1, (uchar *) & (g->a.f[12])); /* initialise IV */
        for (i = 0; i < 16; i++) g->Y_0[i] = g->a.f[i];
    }
    else
    {
        g->status = GCM_ACCEPTING_CIPHER;
        GCM_ghash(g, iv, niv); /* GHASH(H,0,IV) */
        GCM_wrap(g);
        for (i = 0; i < 16; i++)
        {
            g->a.f[i] = g->stateX[i];
            g->Y_0[i] = g->a.f[i];
            g->stateX[i] = 0;
        }
        g->lenA[0] = g->lenC[0] = g->lenA[1] = g->lenC[1] = 0;
    }
    g->status = GCM_ACCEPTING_HEADER;
}

/* SU= 24 */
/* Add Header data - included but not encrypted */
int core::GCM_add_header(gcm* g, char *header, int len)
{
    /* Add some header. Won't be encrypted, but will be authenticated. len is length of header */
    int i, j = 0;
    if (g->status != GCM_ACCEPTING_HEADER) return 0;

    while (j < len)
    {
        for (i = 0; i < 16 && j < len; i++)
        {
            g->stateX[i] ^= header[j++];
            g->lenA[1]++;
            if (g->lenA[1] == 0) g->lenA[0]++;
        }
        gf2mul(g);
    }
    if (len % 16 != 0) g->status = GCM_ACCEPTING_CIPHER;
    return 1;
}

/* SU= 48 */
/* Add Plaintext - included and encrypted */
int core::GCM_add_plain(gcm *g, char *cipher, char *plain, int len)
{
    /* Add plaintext to extract ciphertext, len is length of plaintext.  */
    int i, j = 0;
    unsign32 counter;
    uchar B[16];
    if (g->status == GCM_ACCEPTING_HEADER) g->status = GCM_ACCEPTING_CIPHER;
    if (g->status != GCM_ACCEPTING_CIPHER) return 0;

    while (j < len)
    {
        counter = pack((uchar *) & (g->a.f[12]));
        counter++;
        unpack(counter, (uchar *) & (g->a.f[12])); /* increment counter */
        for (i = 0; i < 16; i++) B[i] = g->a.f[i];
        AES_ecb_encrypt(&(g->a), B);       /* encrypt it  */

        for (i = 0; i < 16 && j < len; i++)
        {
            cipher[j] = plain[j] ^ B[i];
            g->stateX[i] ^= cipher[j++];
            g->lenC[1]++;
            if (g->lenC[1] == 0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len % 16 != 0) g->status = GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 48 */
/* Add Ciphertext - decrypts to plaintext */
int core::GCM_add_cipher(gcm *g, char *plain, char *cipher, int len)
{
    /* Add ciphertext to extract plaintext, len is length of ciphertext. */
    int i, j = 0;
    unsign32 counter;
    char oc;
    uchar B[16];
    if (g->status == GCM_ACCEPTING_HEADER) g->status = GCM_ACCEPTING_CIPHER;
    if (g->status != GCM_ACCEPTING_CIPHER) return 0;

    while (j < len)
    {
        counter = pack((uchar *) & (g->a.f[12]));
        counter++;
        unpack(counter, (uchar *) & (g->a.f[12])); /* increment counter */
//printf("len= %d  counter= %d\n",len,counter);

        for (i = 0; i < 16; i++) B[i] = g->a.f[i];
        AES_ecb_encrypt(&(g->a), B);       /* encrypt it  */
        for (i = 0; i < 16 && j < len; i++)
        {
            oc = cipher[j];
            plain[j] = cipher[j] ^ B[i];
            g->stateX[i] ^= oc;
            j++;
            g->lenC[1]++;
            if (g->lenC[1] == 0) g->lenC[0]++;
        }
        gf2mul(g);
    }
    if (len % 16 != 0) g->status = GCM_NOT_ACCEPTING_MORE;
    return 1;
}

/* SU= 16 */
/* Finish and extract Tag */
void core::GCM_finish(gcm *g, char *tag)
{
    /* Finish off GHASH and extract tag (MAC) */
    int i;

    GCM_wrap(g);

    /* extract tag */
    if (tag != NULL)
    {
        AES_ecb_encrypt(&(g->a), g->Y_0);       /* E(K,Y0) */
        for (i = 0; i < 16; i++) g->Y_0[i] ^= g->stateX[i];
        for (i = 0; i < 16; i++)
        {
            tag[i] = g->Y_0[i];
            g->Y_0[i] = g->stateX[i] = 0;
        }
    }
//    g->lenA[0] = g->lenC[0] = g->lenA[1] = g->lenC[1] = 0;
    g->status = GCM_FINISHED;
    AES_end(&(g->a));
//    g->status = GCM_ACCEPTING_HEADER;
}

/* AES-GCM Encryption of octets, K is key, H is header,
   P is plaintext, C is ciphertext, T is authentication tag */
void core::AES_GCM_ENCRYPT(octet *K, octet *IV, octet *H, octet *P, octet *C, octet *T)
{
    gcm g;
    GCM_init(&g, K->len, K->val, IV->len, IV->val);
    GCM_add_header(&g, H->val, H->len);
    GCM_add_plain(&g, C->val, P->val, P->len);
    C->len = P->len;
    GCM_finish(&g, T->val);
    T->len = 16;
}

/* AES-GCM Decryption of octets, K is key, H is header,
   P is plaintext, C is ciphertext, T is authentication tag */
void core::AES_GCM_DECRYPT(octet *K, octet *IV, octet *H, octet *C, octet *P, octet *T)
{
    gcm g;
    GCM_init(&g, K->len, K->val, IV->len, IV->val);
    GCM_add_header(&g, H->val, H->len);
    GCM_add_cipher(&g, P->val, C->val, C->len);
    P->len = C->len;
    GCM_finish(&g, T->val);
    T->len = 16;
}


// Compile with
// gcc -O2 gcm.c aes.c -o gcm.exe
/* SU= 16
*/

 static void hex2bytes(char *hex,char *bin) 
 { 
  int i; 
  char v; 
  int len=strlen(hex); 
  for (i = 0; i < len/2; i++) { 
         char c = hex[2*i]; 
         if (c >= '0' && c <= '9') { 
             v = c - '0'; 
         } else if (c >= 'A' && c <= 'F') { 
             v = c - 'A' + 10; 
         } else if (c >= 'a' && c <= 'f') { 
             v = c - 'a' + 10; 
         } else { 
             v = 0; 
         } 
         v <<= 4; 
         c = hex[2*i + 1]; 
         if (c >= '0' && c <= '9') { 
             v += c - '0'; 
         } else if (c >= 'A' && c <= 'F') { 
             v += c - 'A' + 10; 
         } else if (c >= 'a' && c <= 'f') { 
             v += c - 'a' + 10; 
         } else { 
             v = 0; 
         } 
         bin[i] = v; 
     } 
 } 


int main()
{
    int i;

    char* KT=(char *)"d11904fc780cfbd39dde1e1648a55946";
    char* NT=(char *)"1404983c7e637854e0618d27";

    int lenK=strlen(KT)/2;
    int lenIV=strlen(NT)/2;

// TAG= 551737f7e9a200cfa1041d4e75c18f4f
// Correct TAG= 551737f7e9a200cfa1041d4e75c18f4f

    char* HT1=(char *)"1703030119";
    char* CT1=(char *)"8328ac29b07125a06da9f0fc0fbce1c542a6fffd6cf32e159e4c73252f26003ea069dfca6cc89d594a5f31412af8f787eb5ee99c5ad70fdfb4cf0e2fb0412566a975bf99c8c9a796d11bd77d61c5deb78e11a12ac7aa05c5e3423bfd07b41dd9afad4958ee444c6cd16252cb361ed324cfbef0268a8cd3b1c9e863e648ab7e8ca8fa0d2fd4af2df88b6839cc9038977a70b8652f8528345d97b6085f2d8400fbd24028ad23198e9def5579a724fcdb3b2cd35f0559c82bd09fe3d09e034011c830049be850300dbb773377ab175ad9ac3bb5dc80be573ebf15826ad367424eb069d51136070bd727c878eb4a5ebe99c6f47282a2217076d1be6a5436cd024e905f873faf50146d02a2";

// TAG= 84e677bc7ad4b91078d28989ec6d4bb9
// Correct TAG= 5251b77076e6b94c28790156f8c639f1
    char* HT2=(char *)"1703030a13";
    char* CT2=(char *)"14f3ed2e3c0d679312402da9aed3cd403b67af408f7e53df9464340e0f2f95a660a35f5540ae2615b2f91f69746f1c688a190278362cfe6575816cf334c8f020e6f37d7e08b3769e2b52b4f3a300de90b9d197f8a7b50caec282772c1ef0129e155df682c85e0ba85cb661b3dac91757361d2418aa579f4be91362ad26bd684bb98d4df9eac23f8f1067188e22ad3027bfe0b496536087edcc60f353a12726a3fe5d16634236b71f810635a547d1b3c56d803c9a6719ad43281088a6bed77336e728e062309c1b5d9106f7a79b72663b86b20d7d2a91e734750205d004afc626f0e062c97dd659994c19f90e27e128d74297a03b8ffa64f180fc8fa0890d75913a571f532ff85c6683dfb293e43cf05fda577d5672b969348ca1b85e322e5e3555fb04c36164274ab9fe121d5d49fce1bdb8ac80e4bf2dbdac54ae58ed57bbced531646e292ff9e15e437847da38e5db259282169c11b3c615537a50e4bc20c0cad375f521d2d65cac53b77ed8bb05a8325d131ce52bb81f89192cc2ff77cdfd0050c120db36aade19a90ef13c75e8ee7bfe274e54f3a497fdcab874c6b2a292bd7c717c2455796f32d471c3e8b9fabf0332626ba1a531de0198ae19664bbe7453154a199c6c1f550267d6b039071fbd34cc6b7945c4a39578a5216426f14d93605b0e1a329c80415c83cfd6872442c3aa16b00426d45236a9e5674a0653796d610d9fbc79110fb7ac9e8aa10cef6800f8b7a702618c508f5187d7b4d4ba984b3f0981590251a01d75e931fca7e3c5b8590fea8f4494734a9fd9d73eac71a1a76bc782ae29be68969fc85b4c291ec376e2466bc49b14f5b665ec5d70bb2dcd432014a31514473fdf191eafc24c9ce3bf21bebf354a7aec70d4205753614774b9188a17ede26fb6c5c0ea78a164c1a0cc7b01a785604bba51d7ab120a16a56571191b5f47fab102d91b32ae87a2ee2c231dceee105eefda4f5be66e172fe8b378a714ad2a4373b6134c0449100b71dbfbe6dd477116d2bab395d724b2b50cabce1432849f56c7c2ad9d89c885d2510c5d7b36a1c72d83eb242870a7de8764fab95a28179ba92b765a594187607e7c347b5ba31df91e7fa26c8fa4631aadc993378e20521c2b0c59940d30e5099cfc63f7ed5c9693b5eaa0224d36f20cdb4d91f2457c6b92650076661ea794a825177621b3ebc89512fca239df271e1632864fa156848346fc4fec00bb3ed4787f1200cb757ccbd78173094c403e6fb4605fe170f5e502c47dd96c0b722443afcd55335803962f23f25f78a989e8ae1f9ab12ca9d03234a5c85a8eaccde7e8c74a37dc86a9291934303f44ea6fae319b75b5b0760b8016518d0202200c2c257067ea82717792aadd48d3e68a31a0d434809b067b71e76ac58ca06b230a58f5a818929bce9b48f1d8afbc0e3ff4a78190affac9ce92d6bd82a397995e507c2d3b6789e4ea7bbd820696b759be6a9a2e1d56066c34de5e84a44839c0ed62f00bfb46b919957be83dde8c008d06596ac71841566047222ddc40622d91a7b83e2c140f8b6a7320050715d254246d3b7ba1ff637f31bdaae58cb6c986a1e314845d34f099215ec8d654372685cade4a4125a5914abc573966b27d50e95bea083d7c42d386a49be7909a75d5df487848a2495108b858d925721167aff77ca7f11c9275435f4aefd48904e6988930ec96703e401f6ebd96b68de4b2c3bd9dc98dc7aba1e20c1659f5aa1fdc37707037dffc0027f733e7f9812bd73415e28951ad5c059a246ae11794e9a494dc31b344e5dc1af0a9ad52aa623bae1824fefd719686579d5b30343a6aa3e8858fcf37eb35870e8ffcbc41cfb424ce8f5113ab21d20d8333d29adcb1bf48c89725e30e453a6b49caa5fb7307a84e390fbf4630f05644ff7c9418e6d8aea188c09395bced130846d75fe47cd4694553257b6a050bf406de027e2d44efde4273c184c24043a9fac7849f0a55d3970c129e28c769ab7e1697f4ee70a3a4d8bfdc1ab020e0ba5f27a74b5568f88488177dca6fef15d7c706603369fe458dea1f266096fbc0ea5a447978fa294e3761d80cfbc56e1ec13a2c29756fccbca6d075dd54149714e166f49e525bf685f8d790740a4282af8e52e769b87b5b626fb1cbd23caafdc52e78277ee7bd7a4ced5bc4b57447dbbb93b718134d9ef8e0169d5dc8cf8b013ed03bf48b9c9a2e10a93ea70af64b699c59531421cc925c0f2b168e2ca5efd5da93c33c34625d9bae29bff0120058cc1be1b1bbce4af2962f9bd7fb985495af234131b1cea5d13c2a52c8cef357d0b2374a35a7118ad9017707b0805058323aaafdf8ae46c6145877d38cfc4885850da55b9ff1f3ea15766a442718abf7c291f87c80c95c904eb2ee357fbb5a043f77951d680b0d530cb06f0d7b22ecf224a83803f3709499c3b40ec37aa8231795da27edcb96fdd09f4e45c8257ad33f80d6da2daee2c76df97b314b50146c5cb6012ddb14a968a473bc5c0289c834ca7017eb21faa557cdd80d223e2905e787eba6fa7062c08beba1e352a7745b50c86fc8dd052a0d249ac4da055aca2877098f1572e1589004b5cf188a1fefa9efda5aefd8890813f344de86eabc50f8c4d7403f32fb866879e9f9a3691347a80aef2d74777d250a34306bf1b03479fdf74c8616ec6934bc70adeb20154a8721505095ab2b70d781304d25b2b906c1de28a885dd6161f9ebf5c7eb9e4540f25162b814d9ed1113956171842ed4e234277cfe53e6e5e418c745f87abd36112c65bc007e7efe12b8c4c57b041c58a49951db9f644f1489818c5c6d8233c811b95357d529f388d255780b194576c29465215c3f4f44a67743b061fc9a2e282045fe217d895803d2072fd2cc94b9041a9d62c3b68e8e4b2ef0e879cfb067d4088888c8ae1b88f682602a0c8b092b8ac0141fee0d61825e7dca4fccf59297d8492fa6f48de382c19d8d9c67901a90e37b85f16a4f4e318d1defcaf9a63d5900e8dab3c73d4fcf7eebfb41e1317e1aee88d31e00357e553a88747e434f095f73aa99fae728ecc836e05bea8811d6bb511c3dee28d7ed87f7da3553127fd682d16557e985fed86d0b5474f5d468619ee9bf44976f24ccc9a33f459eaa40172eb1cb6f8142a82885716f1e3b06406d7058907e1b4426298ae94c4022ce43680383284ccf67c280f3ab946ea82e41f1b4dd5ddf14ca33798d921272395f35bec040809b7957c73c8d56acf7d40a3f60d2fdba50d183cca9b674f10e130bcf704a3d1626b8886d102ff717cd55a2682a7664622f10e49da07d673378c25d4c5b91fbb45a44e32c5c661a444a02ba5085b9b01630735aaa73917f42624e0a3fdd698dfb9f140f2786512821bbf7ef5a2df918bbcc2716246232045a9e825887bb280def634641d9b74d7c8d59538b340195d5209d5b504ba0a6cbb7c1ae3a0921e93324e1286c85119a26b78dc91cf529014741eedae8788edb0b18946ad894b6c7b954c9b25c72968a8c458610b98d69634f803c912debc81ae681b1fd50f26a9b4f705484be29db7d1a5ecf04098527c7e9ec1f2cd912891a24d794b740aec01295d08e437c645aa845d1abe68d07cd8bb9758a5860";

    char T[16];   // Tag
    char K[16];   // AES Key
    char H1[64];   // Header - to be included in Authentication, but not encrypted
    char H2[64];   // Header - to be included in Authentication, but not encrypted
    char N[100];   // IV - Initialisation vector
    char M1[8000];  // Plaintext to be encrypted/authenticated
    char M2[8000];  // Plaintext to be encrypted/authenticated
    char C1[8000];  // Ciphertext
    char C2[8000];  // Ciphertext
    char P[8000];  // Recovered Plaintext

    gcm g;


    hex2bytes(NT, N);
    hex2bytes(KT, K);
    hex2bytes(CT1, C1);
    hex2bytes(HT1, H1);
    hex2bytes(CT2, C2);
    hex2bytes(HT2, H2);

    printf("lenK= %d\n",lenK);

    int len=strlen(CT1)/2;
    int lenH=strlen(HT1)/2;

//    printf("Ciphertext=\n");
//    for (i=0;i<len;i++) printf("%02x",(unsigned char)C1[i]);
    printf("\n");

    GCM_init(&g,16,K,lenIV,N);
    GCM_add_header(&g,H1,lenH);
    GCM_add_cipher(&g,M1,C1,len);
    GCM_finish(&g,T);

    printf("Plaintext=\n");
    for (i=0;i<len;i++) printf("%02x",(unsigned char)M1[i]);
    printf("\n");

    printf("Tag=\n");
    for (i=0;i<16;i++) printf("%02x",(unsigned char)T[i]);
    printf("\n");
/*
    len=strlen(CT2)/2;
    lenH=strlen(HT2)/2;

//    printf("Ciphertext=\n");
//    for (i=0;i<len;i++) printf("%02x",(unsigned char)C2[i]);

    printf("\n");

    GCM_init(&g,16,K,lenIV,N);
    GCM_add_header(&g,H2,lenH);
    GCM_add_cipher(&g,M2,C2,len);
    GCM_finish(&g,T);

    printf("Plaintext=\n");
    for (i=0;i<len;i++) printf("%02x",(unsigned char)M2[i]);
    printf("\n");

    printf("Tag=\n");
    for (i=0;i<16;i++) printf("%02x",(unsigned char)T[i]);
    printf("\n");
*/
}


