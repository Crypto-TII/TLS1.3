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

/* IBE 128-bit API Functions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "randapi.h"
#include "tls_bfibe.h"

#if CHUNK == 32
using namespace B384_29;
#else
using namespace B384_58;
#endif

using namespace BLS12381;

#define ROUNDUP(a,b) ((a)-1)/(b)+1

/* Encode octet to curve point on G2 */
static void h1(char *identity,ECP2 *Qid)
{
    int j,k,m,L;
    char okm[128],fd[64],dst[64],id[100];
    octet ID = {0,sizeof(id),id};
    octet DST = {0, sizeof(dst), dst};
    OCT_jstring(&DST,(char *)"BLS12381G1_XMD:SHA-256_SVDW_NU_BFIBE"); // Domain Separation Tag
    OCT_jstring(&ID,identity);
    BIG q,r,w;
    FP u1,u2;
    FP2 u;
    DBIG dx;
    octet OKM = {0,sizeof(okm),okm};
    BIG_rcopy(q,Modulus);
    k=BIG_nbits(q);
    BIG_rcopy(r, CURVE_Order);
    m=BIG_nbits(r);
    L=ROUNDUP(k+ROUNDUP(m,2),8);
    XOF_Expand(SHAKE128,&OKM,2*L,&DST,&ID);
    for (j=0;j<L;j++)
        fd[j]=OKM.val[j];
        
    BIG_dfromBytesLen(dx,fd,L);
    BIG_dmod(w,dx,q);
    FP_nres(&u1,w);

    for (j=0;j<L;j++)
        fd[j]=OKM.val[L+j];
       
    BIG_dfromBytesLen(dx,fd,L);
    BIG_dmod(w,dx,q);
    FP_nres(&u2,w);

    FP2_from_FPs(&u,&u1,&u2);

    ECP2_map2point(Qid,&u);
    ECP2_cfp(Qid);
    ECP2_affine(Qid);
}

/* create random r in Zq from U and V, and rP */
static void h3(octet *U,octet *V,BIG r,ECP *rP)
{
    int i;
    BIG q;
    csprng RNG; 
    BIG_rcopy(q, CURVE_Order);
    char raw[128];
    octet RAW = {128, sizeof(raw), raw};
	sha3 sh;
	SHA3_init(&sh,SHAKE256);
	for (i=0;i<U->len;i++) {
		SHA3_process(&sh,U->val[i]&0xff);
    } 
    if (V!=NULL)
    {
	    for (i=0;i<V->len;i++) {
		    SHA3_process(&sh,V->val[i]&0xff); 
        }
    }
	SHA3_shake(&sh,raw,128);
    CREATE_CSPRNG(&RNG, &RAW);
    BIG_randtrunc(r, q, 2 * CURVE_SECURITY_BLS12381, &RNG);
    ECP_generator(rP);
    PAIR_G1mul(rP,r);
} 

/* hash input octet to 32 bytes */
static void h4(octet *I,octet *O)
{
	sha3 sh;
	SHA3_init(&sh,SHA3_HASH256);
	for (int i=0;i<I->len;i++) {
		SHA3_process(&sh,I->val[i]&0xff);
    }  
    SHA3_hash(&sh,O->val);
    O->len=32;
} 

/* Client secret CST=s*IDHTS where IDHTS is server ID hashed to a curve point, and s is the master secret */
static void bfibe_get_id_secret(BIG s, char *id, octet *SK)
{
    ECP2 Q;
    char server_id[100],hid[256];
    octet HID = {0, sizeof(hid), hid};
    h1(id,&Q); // Hash to curve
    PAIR_G2mul(&Q, s);
    ECP2_toOctet(SK, &Q, false); // change to TRUE for point compression 
    
} 

/* Extract TA public PK=S*Q where Q is fixed generator in G2 and S is master secret */
static void bfibe_get_ta_public(BIG s, octet *PK)
{
    BIG r;
    ECP P;
  
    BIG_rcopy(r, CURVE_Order);
    ECP_generator(&P);
   
    PAIR_G1mul(&P, s);
    ECP_toOctet(PK, &P, false);
} 

char *tapk=(char *)"0402d506a111d406dd0ad9d64b6515c4e15fd28ab45595b89817871d9220f0242c7b7ef1800ad8e6a8f047100088702ac8042add1af478ae20672c6670959ae36f19dcdee948f6b40a3498af69d708fbf15e81b536dacac484a697a59f3742063b";

/* IBE Encrypt */
bool BFIBE_CCA_ENCRYPT(char *ID,octet *R32,octet *M,octet *CT)
{
    ECP rP,Ppub;
    ECP2 Qid;
    BIG r;
    FP12 g;

    char u[2*PFS_BLS12381+1],z[12*PFS_BLS12381],sigma[32],mask[32],v[32],w[32];
    octet SIGMA={0,sizeof(sigma),sigma};
    octet MASK={0,sizeof(mask),mask};
    octet U = {0, sizeof(u), u};
    octet V = {0, sizeof(v), v};
    octet W = {0, sizeof(w), w};
    octet Z = {0, sizeof(z), z};

	sha3 sh;
	SHA3_init(&sh,SHAKE256);
	for (int i=0;i<R32->len;i++) {
		SHA3_process(&sh,R32->val[i]&0xff);
    }     
    SHA3_shake(&sh,SIGMA.val,32);   // random sigma
    SHA3_shake(&sh,M->val,32);      // generate encapsulated 

    M->len=32;
    SIGMA.len=32;

    h1(ID,&Qid);                    // HID=H1(ID)
    h3(&SIGMA,M,r,&rP);             // r,rP=H3(sigma,m)
    h4(&SIGMA,&MASK);               // MASK=H4(sigma)

    OCT_copy(&W,M);
    OCT_xor(&W,&MASK);

    OCT_fromHex(&U,tapk);
    if (!ECP_fromOctet(&Ppub,&U)) return false;

    PAIR_G1mul(&Ppub,r);
    ECP_toOctet(&U,&rP,false);
    PAIR_ate(&g, &Qid, &Ppub); // e(HID,r.Ppub)
    PAIR_fexp(&g);
    FP12_toOctet(&Z,&g);

    h4(&Z,&MASK);

    OCT_copy(&V,&SIGMA);
    OCT_xor(&V,&MASK);

    OCT_empty(CT);
    OCT_joctet(CT,&U);
    OCT_joctet(CT,&V);
    OCT_joctet(CT,&W);
 
    return true;
} 

/* IBE Decrypt */
bool BFIBE_CCA_DECRYPT(octet *SK,octet *CT,octet *M)
{
    ECP rPc,rP;
    ECP2 Did;
    FP12 g;
    BIG r;
 
    char u[2*PFS_BLS12381+65],z[12*PFS_BLS12381],sigma[32],v[64],w[32];
    octet U={0,sizeof(u),u};
    octet W={0,sizeof(w),w};
    octet V={0,sizeof(v),v};
    octet Z = {0, sizeof(z), z};
    octet SIGMA={0,sizeof(sigma),sigma};
   
    int res=0;
    OCT_copy(&U,CT);
    OCT_chop(&U,&V,2*PFS_BLS12381+1);
    OCT_chop(&V,&W,32);
    if (!ECP_fromOctet(&rP,&U)) return false;
    if (!ECP2_fromOctet(&Did,SK)) return false;

    PAIR_ate(&g,&Did,&rP);  // e(Did,U)
    PAIR_fexp(&g);
    FP12_toOctet(&Z,&g);
    h4(&Z,&SIGMA);

    OCT_xor(&SIGMA,&V);
    h4(&SIGMA,M);
    OCT_xor(M,&W);
    h3(&SIGMA,M,r,&rPc);  
    if (!ECP_equals(&rP,&rPc)) return false;
    
    return true;
} 

char *idsk=(char *)"040ec014966d3442e85ed19b46044d9655d8ed91ef05e6678e57a51cfd9202c8dad2c854850b09fc919b6cb000a2f5b05801b767a87194d62d45cb1b1a9cd15b63ea733770361de22f64946631c2c21826d8abf884e4d07159d54c91b79662e2e4050ae782a9fb9394853669540b4cb1f46098ca690bd572b9c47587ca12a2f2c268e1a22ebc0d752f95bcf926a8b6e2cb1452dc7bf03eab18c5b68822b0da20279d1e8997a759637abdffec93f4c985f9256deed1cca5c50e2c37ae6c10c67c13";

/*
#define LOOPS 100

int main()
{
    char *id=(char *)"localhost";
    char r32[32],sk[256],m[32],ct[2*PFS_BLS12381+65],pk[4*PFS_BLS12381+1];
    octet R32={32, sizeof(r32), r32};
    octet SK = {0, sizeof(sk), sk};
    octet PK = {0, sizeof(pk), pk};
    octet M = {0, sizeof(m), m};
    octet CT = {0, sizeof(ct), ct};

//    BIG s;
//    ECP rP;
//
//    for (int i=0;i<32;i++)
//        r32[i]=i+5;
//
//    h3(&R32,NULL, s, &rP);
//    //OCT_output(&S);

//    bfibe_get_id_secret(s, id, &SK);
//    printf("SK= "); OCT_output(&SK);
//    bfibe_get_ta_public(s, &PK);
//    printf("PK= "); OCT_output(&PK);


    OCT_fromHex(&SK,idsk);

    for (int i=0;i<LOOPS;i++)
    {
        for (int j=0;j<32;j++) {
            r32[j]=((i+j)%256);
        }

        BFIBE_CCA_ENCRYPT(id,&R32,&M,&CT);

        printf("EM= ");
        OCT_output(&M);

        BFIBE_CCA_DECRYPT(&SK,&CT,&M);
        printf("DM= ");
        OCT_output(&M);
    }
    return 0;
}
*/
