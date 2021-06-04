/* X.509 Functions */

#include <stdio.h>
#include "tls_octads.h"  
#include "tls_x509.h"

// Some ASN.1 tags

#define ANY 0x00
#define SEQ 0x30
#define OID 0x06
#define INT 0x02
#define NUL 0x05
#define ZER 0x00
#define UTF 0x0C
#define UTC 0x17
#define GTM 0x18
#define LOG 0x01
#define BIT 0x03
#define OCT 0x04
#define STR 0x13
#define SET 0x31
#define IA5 0x16
#define EXT 0xA3
#define DNS 0x82

// Define some OIDs

// Elliptic Curve with SHA256
static unsigned char eccsha256[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
static octad ECCSHA256 = {8, sizeof(eccsha256), (char *)eccsha256};

// Elliptic Curve with SHA384
static unsigned char eccsha384[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
static octad ECCSHA384 = {8, sizeof(eccsha384), (char *)eccsha384};

// Elliptic Curve with SHA512
static unsigned char eccsha512[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};
static octad ECCSHA512 = {8, sizeof(eccsha512), (char *)eccsha512};

// EC Public Key - Elliptic curve public key cryptography
static unsigned char ecpk[7] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static octad ECPK = {7, sizeof(ecpk), (char *)ecpk};

// ED Public Key - Elliptic curve EdDSA (Ed25519) Signature
static unsigned char edpk[3] = {0x2B, 0x65, 0x70};              
static octad EDPK = {3, sizeof(edpk),(char *)edpk};

// C25519 curve
static unsigned char prime25519[9] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}; /*****/
static octad PRIME25519 = {9, sizeof(prime25519), (char *)prime25519};

// NIST256 curve - (NIST) P-256
static unsigned char prime256v1[8] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};
static octad PRIME256V1 = {8, sizeof(prime256v1), (char *)prime256v1};

// NIST384 curve
static unsigned char secp384r1[5] = {0x2B, 0x81, 0x04, 0x00, 0x22};
static octad SECP384R1 = {5, sizeof(secp384r1), (char *)secp384r1};

// NIST521 curve
static unsigned char secp521r1[5] = {0x2B, 0x81, 0x04, 0x00, 0x23};
static octad SECP521R1 = {5, sizeof(secp521r1), (char *)secp521r1};

// RSA Public Key - RSAES-PKCS1-v1_5
static unsigned char rsapk[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
static octad RSAPK = {9, sizeof(rsapk), (char *)rsapk};

// RSA with SHA256
static unsigned char rsasha256[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
static octad RSASHA256 = {9, sizeof(rsasha256), (char *)rsasha256};

// RSA with SHA384
static unsigned char rsasha384[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c};
static octad RSASHA384 = {9, sizeof(rsasha384), (char *)rsasha384};

// RSA with SHA512
static unsigned char rsasha512[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d};
static octad RSASHA512 = {9, sizeof(rsasha512), (char *)rsasha512};



// Cert details
// countryName
static unsigned char cn[3] = {0x55, 0x04, 0x06};
octad X509_CN = {3, sizeof(cn), (char *)cn};

// stateName
static char sn[3]= {0x55,0x04,0x08};
octad X509_SN= {3,sizeof(sn),sn};

// localName
static char ln[3]= {0x55,0x04,0x07};
octad X509_LN= {3,sizeof(ln),ln};

// orgName
static unsigned char on[3] = {0x55, 0x04, 0x0A};
octad X509_ON = {3, sizeof(on), (char *)on};

// unitName
static char un[3]= {0x55,0x04,0x0B};
octad X509_UN= {3,sizeof(un),un};

// myName
static char mn[3]= {0x55,0x04,0x03};
octad X509_MN= {3,sizeof(mn),mn};

// emailName
static unsigned char en[9] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01};
octad X509_EN = {9, sizeof(en), (char *)en};

// Extensions
// Alt Name
static char an[3]={0x55,0x1D,0x11};
octad X509_AN = {3, sizeof(an),an};

// Key Usage
static char ku[3]={0x55,0x1d,0x0f};
octad X509_KU = {3,sizeof(ku),ku};

// Basic Constraints
static char bc[3]={0x55,0x1d,0x13};
octad X509_BC = {3,sizeof(bc),bc};

/* Check expected TAG and return ASN.1 field length. If tag=0 skip check. */
static int getalen(int tag, char *b, int j)
{
    int len;

    if (tag != 0 && (unsigned char)b[j] != tag) return -1; // not a valid tag
    j++;

    if ((unsigned char)b[j] == 0x81)
    {
        j++;
        len = (unsigned char)b[j];
    }
    else if ((unsigned char)b[j] == 0x82)
    {
        j++;
        len = 256 * b[j++];
        len += (unsigned char)b[j];
    }
    else
    {
        len = (unsigned char)b[j];
        if (len > 127) return -1;
    }
    return len;
}

/* jump over length field */
static int skip(int len)
{
    if (len < 128) return 2;
    if (len < 256) return 3;
    return 4;
}

/* round length up to nearest 8-byte length */
static int bround(int len)
{
    if (len % 8 == 0) return len;
    return len + (8 - len % 8);

}

// Input private key in PKCS#8 format
// e.g. openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
// e.g. openssl req -x509 -nodes -days 3650 -newkey ec:<(openssl ecparam -name prime256v1) -keyout key.pem -out ecdsacert.pem
// extract private key from uncompressed key.pem into octad
// For RSA octad = p|q|dp|dq|c where pk->len is multiple of 5
// For ECC octad = k
pktype X509_extract_private_key(octad *c,octad *pk)
{
    int i, j, k, fin, len, rlen, flen, sj, ex;
    char soid[9];
    octad SOID = {0, sizeof(soid), soid};
    pktype ret;

    ret.type = 0;
    ret.hash = 0;
    j=0;

    len = getalen(SEQ, c->val, j);  // Check for expected SEQ clause, and get length
    if (len < 0) return ret;        // if not a SEQ clause, there is a problem, exit
    j += skip(len);                 // skip over length to clause contents. Add len to skip clause

    if (len + j != c->len) return ret;

    len = getalen(INT, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // jump over serial number clause (if there is one)

    len = getalen(SEQ, c->val, j); 
    if (len < 0) return ret;        
    j += skip(len);

// extract OID
    len = getalen(OID, c->val, j);
    if (len < 0) return ret;
    j += skip(len);

    fin = j + len;
    SOID.len = len;
    for (i = 0; j < fin; j++)
        SOID.val[i++] = c->val[j];
    j=fin;

    if (OCT_compare(&EDPK, &SOID)) 
    { // Its an Ed25519 key
        len = getalen(OCT, c->val, j);
        if (len < 0) return ret;
        j += skip(len);
        len = getalen(OCT, c->val, j);
        if (len < 0) return ret;
        j += skip(len);
        rlen=32;
        pk->len=rlen;
        for (i=0;i<rlen-len;i++)
            pk->val[i]=0;
        for (i=rlen-len;i<rlen;i++)
            pk->val[i]=c->val[j++];
        ret.type = X509_ECD;
        ret.curve = USE_C25519;
    }

    if (OCT_compare(&ECPK, &SOID))
    { // Its an ECC key
        len = getalen(OID, c->val, j);
        if (len < 0) return ret;
        j += skip(len);

        fin = j + len;
        SOID.len = len;
        for (i = 0; j < fin; j++)
            SOID.val[i++] = c->val[j];
        j=fin;           
        
        len = getalen(OCT, c->val, j);
        if (len < 0) return ret;
        j += skip(len);

        len = getalen(SEQ, c->val, j); 
        if (len < 0) return ret; 
        j += skip(len);

        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len) + len; // jump over version

        len = getalen(OCT, c->val, j);
        if (len < 0) return ret;
        j += skip(len);

        ret.type = X509_ECC;
        if (OCT_compare(&PRIME256V1, &SOID)) {
            ret.curve = USE_NIST256;
            rlen=32;
        }
        if (OCT_compare(&SECP384R1, &SOID)) {
            ret.curve = USE_NIST384;
            rlen=48;
        }
        if (OCT_compare(&SECP521R1, &SOID)) {
            rlen=66;
            ret.curve = USE_NIST521;
        }

        pk->len=rlen;
        for (i=0;i<rlen-len;i++)
            pk->val[i]=0;
        for (i=rlen-len;i<rlen;i++)
            pk->val[i]=c->val[j++];

    }
    if (OCT_compare(&RSAPK, &SOID))
    { // Its an RSA key
        len = getalen(NUL, c->val, j);
        if (len<0) return ret;
        j += skip(len);

        len = getalen(OCT, c->val, j);
        if (len < 0) return ret;
        j += skip(len);

        len = getalen(SEQ, c->val, j); 
        if (len < 0) return ret; 
        j += skip(len);

        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len) + len; // jump over version

        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len) + len; // jump over n

        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len) + len; // jump over e

        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len) + len; // jump over d


        len = getalen(INT, c->val, j);
        if (len < 0) return ret;
        j += skip(len); // get p

        if (c->val[j] == 0)
        { // skip leading zero
            j++;
            len--;
        }
        rlen=bround(len);
        for (i=0;i<rlen-len;i++)
            pk->val[i]=0;

        for (i=rlen-len;i<rlen;i++)
            pk->val[i]=c->val[j++];

        flen=rlen;          // should be same length for all
        for (k=1;k<5;k++)
        {
            len = getalen(INT,c->val,j);
            if (len<0) return ret;
            j += skip(len);  // get q,dp,dq,c
            if (c->val[j] == 0)
            { // skip leading zero
                j++;
                len--;
            }
            rlen=bround(len);
            if (rlen!=flen) return ret;
            for (i=0;i<rlen-len;i++)
                pk->val[i]=0;
            for (i=rlen-len;i<rlen;i++)
                pk->val[k*flen+i]=c->val[j++];
        }
        pk->len=5*flen;
        ret.type = X509_RSA;
        ret.curve = 16 * flen;
    }
    return ret;
}

//  Input signed cert as octad, and extract signature
//  Return 0 for failure, ECC for Elliptic Curve signature, RSA for RSA signature
//  Note that signature type is not provided here - its the type of the public key that
//  is used to verify it that matters, and which determines for example the curve to be used!

pktype X509_extract_cert_sig(octad *sc, octad *sig)
{
    int i, j, k, fin, len, rlen, sj, ex;
    char soid[9];
    octad SOID = {0, sizeof(soid), soid};
    pktype ret;

    ret.type = 0;
    ret.hash = 0;

    j = 0;

    len = getalen(SEQ, sc->val, j); // Check for expected SEQ clause, and get length
    if (len < 0) return ret;        // if not a SEQ clause, there is a problem, exit
    j += skip(len);                 // skip over length to clause contents. Add len to skip clause

    if (len + j != sc->len) return ret;

    len = getalen(SEQ, sc->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // jump over cert to signature OID

    len = getalen(SEQ, sc->val, j);
    if (len < 0) return ret;
    j += skip(len);

    sj = j + len; // Needed to jump over signature OID

// dive in to extract OID
    len = getalen(OID, sc->val, j);
    if (len < 0) return ret;
    j += skip(len);

    fin = j + len;
    SOID.len = len;
    for (i = 0; j < fin; j++)
        SOID.val[i++] = sc->val[j];

    // check OID here..
    if (OCT_compare(&EDPK, &SOID)) 
    {
        ret.type = X509_ECD;
        ret.hash = X509_H512;
    }
    if (OCT_compare(&ECCSHA256, &SOID))
    {
        ret.type = X509_ECC;
        ret.hash = X509_H256;
    }
    if (OCT_compare(&ECCSHA384, &SOID))
    {
        ret.type = X509_ECC;
        ret.hash = X509_H384;
    }
    if (OCT_compare(&ECCSHA512, &SOID))
    {
        ret.type = X509_ECC;
        ret.hash = X509_H512;
    }
    if (OCT_compare(&RSASHA256, &SOID))
    {
        ret.type = X509_RSA;
        ret.hash = X509_H256;
    }
    if (OCT_compare(&RSASHA384, &SOID))
    {
        ret.type = X509_RSA;
        ret.hash = X509_H384;
    }
    if (OCT_compare(&RSASHA512, &SOID))
    {
        ret.type = X509_RSA;
        ret.hash = X509_H512;
    }

    if (ret.type == 0) return ret; // unsupported type

    j = sj; // jump out to signature

    len = getalen(BIT, sc->val, j);
    if (len < 0)
    {
        ret.type = 0;
        return ret;
    }
    j += skip(len);
    j++;
    len--; // skip bit shift (hopefully 0!)

    if (ret.type==X509_ECD)
    {
        rlen = bround(len);
        ex = rlen - len;

        sig->len = rlen;
        i = 0;
        for (k = 0; k < ex; k++)
            sig->val[i++] = 0;

        fin = j + len;
        for (; j < fin; j++)
            sig->val[i++] = sc->val[j];
    }

    if (ret.type == X509_ECC)
    {
        // signature in the form (r,s)
        len = getalen(SEQ, sc->val, j);
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len);

        // pick up r part of signature
        len = getalen(INT, sc->val, j);
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len);

        if (sc->val[j] == 0)
        {
            // skip leading zero
            j++;
            len--;
        }
        rlen = bround(len);

        ex = rlen - len;
        sig->len = 2 * rlen;

        i = 0;
        for (k = 0; k < ex; k++)
            sig->val[i++] = 0;

        fin = j + len;
        for (; j < fin; j++)
            sig->val[i++] = sc->val[j];

        // pick up s part of signature
        len = getalen(INT, sc->val, j);
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len);

        if (sc->val[j] == 0)
        {
            // skip leading zeros
            j++;
            len--;
        }
        rlen = bround(len);
        ex = rlen - len;
        for (k = 0; k < ex; k++)
            sig->val[i++] = 0;

        fin = j + len;
        for (; j < fin; j++)
            sig->val[i++] = sc->val[j];

        if (ret.hash == X509_H256) ret.curve = USE_NIST256;
        if (ret.hash == X509_H384) ret.curve = USE_NIST384;
        if (ret.hash == X509_H512) ret.curve = USE_NIST521;
    }
    if (ret.type == X509_RSA)
    {
        rlen = bround(len);
        ex = rlen - len;

        sig->len = rlen;
        i = 0;
        for (k = 0; k < ex; k++)
            sig->val[i++] = 0;

        fin = j + len;
        for (; j < fin; j++)
            sig->val[i++] = sc->val[j];

        ret.curve = 8*rlen;
    }

    return ret;
}

// Extract certificate from signed cert
int X509_extract_cert(octad *sc, octad *cert)
{
    int i, j, fin, len, k;

    j = 0;
    len = getalen(SEQ, sc->val, j);

    if (len < 0) return 0;
    j += skip(len);

    k = j;

    len = getalen(SEQ, sc->val, j);
    if (len < 0) return 0;
    j += skip(len);

    fin = j + len;
    cert->len = fin - k;
    for (i = k; i < fin; i++) cert->val[i - k] = sc->val[i];

    return 1;
}

// Extract Public Key from inside Certificate
pktype X509_extract_public_key(octad *c, octad *key)
{
    int i, j, fin, len, sj;
    char koid[12];     /*****/
    octad KOID = {0, sizeof(koid), koid};
    pktype ret;

    ret.type = ret.hash = 0;
    ret.curve = -1;

    j = 0;

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len);

    if (len + j != c->len) return ret;

    len = getalen(ANY, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; //jump over version clause

    len = getalen(INT, c->val, j);

    if (len > 0) j += skip(len) + len; // jump over serial number clause (if there is one)

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // jump over signature algorithm

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // skip issuer

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // skip validity

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len) + len; // skip subject

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len); //

    len = getalen(SEQ, c->val, j);
    if (len < 0) return ret;
    j += skip(len);

// ** Maybe dive in and check Public Key OIDs here?
// ecpublicKey & prime256v1, secp384r1 or secp521r1 for ECC
// rsapublicKey for RSA

    sj = j + len;

    len = getalen(OID, c->val, j);
    if (len < 0) return ret;
    j += skip(len);

    fin = j + len;
    KOID.len = len;
    for (i = 0; j < fin; j++)
        KOID.val[i++] = c->val[j];

    ret.type = 0;
    if (OCT_compare(&ECPK, &KOID)) ret.type = X509_ECC;
    if (OCT_compare(&EDPK, &KOID)) ret.type = X509_ECD;
    if (OCT_compare(&RSAPK, &KOID)) ret.type = X509_RSA;

    if (ret.type == 0) return ret;

    if (ret.type == X509_ECC)
    {
        // which elliptic curve?
        len = getalen(OID, c->val, j);
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len);

        fin = j + len;
        KOID.len = len;
        for (i = 0; j < fin; j++)
            KOID.val[i++] = c->val[j];

        if (OCT_compare(&PRIME25519, &KOID)) ret.curve = USE_C25519; /*****/
        if (OCT_compare(&PRIME256V1, &KOID)) ret.curve = USE_NIST256;
        if (OCT_compare(&SECP384R1, &KOID)) ret.curve = USE_NIST384;
        if (OCT_compare(&SECP521R1, &KOID)) ret.curve = USE_NIST521;
    }

    j = sj; // skip to actual Public Key

    len = getalen(BIT, c->val, j);
    if (len < 0)
    {
        ret.type = 0;
        return ret;
    }
    j += skip(len); //
    j++;
    len--; // skip bit shift (hopefully 0!)

// extract key
    if (ret.type == X509_ECC || ret.type == X509_ECD)
    {
        key->len = len;
        fin = j + len;
        for (i = 0; j < fin; j++)
            key->val[i++] = c->val[j];

    }
    if (ret.type == X509_RSA)
    {
        // Key is (modulus,exponent) - assume exponent is 65537
        len = getalen(SEQ, c->val, j);
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len); //

        len = getalen(INT, c->val, j); // get modulus
        if (len < 0)
        {
            ret.type = 0;
            return ret;
        }
        j += skip(len); //
        if (c->val[j] == 0)
        {
            j++;
            len--; // remove leading zero
        }

        key->len = len;
        fin = j + len;
        for (i = 0; j < fin; j++)
            key->val[i++] = c->val[j];

        ret.curve = 8 * len;
    }
    return ret;
}

// Find pointer to main sections of cert, before extracting individual field
// Find index to issuer in cert
int X509_find_issuer(octad *c)
{
    int j, len;
    j = 0;
    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len);

    if (len + j != c->len) return 0;

    len = getalen(ANY, c->val, j);
    if (len < 0) return 0;
    j += skip(len) + len; //jump over version clause

    len = getalen(INT, c->val, j);

    if (len > 0) j += skip(len) + len; // jump over serial number clause (if there is one)

    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len) + len; // jump over signature algorithm

    return j;
}

// Find index to validity period
int X509_find_validity(octad *c)
{
    int j, len;
    j = X509_find_issuer(c);

    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len) + len; // skip issuer

    return j;
}

// Find index to subject in cert
int X509_find_subject(octad *c)
{
    int j, len;
    j = X509_find_validity(c);

    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len) + len; // skip validity

    return j;
}

// Test for a self-signed certificate
int X509_self_signed(octad *c)
{
    int i,m;
    int ksub=X509_find_subject(c);
    int kiss=X509_find_issuer(c);

    int sublen=getalen(SEQ,c->val,ksub);
    int isslen=getalen(SEQ,c->val,kiss);
    if (isslen!=sublen) return 0;
    ksub+=skip(sublen);
    kiss+=skip(isslen);
    for (i=m=0;i<sublen;i++)
        m|=c->val[i+ksub] - c->val[i+kiss];
    if (m!=0) return 0;
    return 1;
}

// NOTE: When extracting cert information, we actually return just an index to the data inside the cert, and maybe its length
// So no memory is assigned to store cert info. It is the callers responsibility to allocate such memory if required, and copy
// cert information into it.

// Find entity property indicated by SOID, given start of issuer or subject field. Return index in cert, flen=length of field

int X509_find_entity_property(octad *c, octad *SOID, int start, int *flen)
{
    int i, j, k, fin, len, tlen;
    char foid[50];  /*****/
    octad FOID = {0, sizeof(foid), foid};

    j = start;

    tlen = getalen(SEQ, c->val, j);
    if (tlen < 0) return 0;
    j += skip(tlen);

    for (k = j; j < k + tlen;)
    {
        // search for Owner OID
        len = getalen(SET, c->val, j);
        if (len < 0) return 0;
        j += skip(len);
        len = getalen(SEQ, c->val, j);
        if (len < 0) return 0;
        j += skip(len);
        len = getalen(OID, c->val, j);
        if (len < 0) return 0;
        j += skip(len);
        fin = j + len; // extract OID
        FOID.len = len;
        for (i = 0; j < fin; j++)
            FOID.val[i++] = c->val[j];
        len = getalen(ANY, c->val, j); // get text, could be any type
        if (len < 0) return 0;

        j += skip(len);
        if (OCT_compare(&FOID, SOID))
        {
            // if its the right one return
            *flen = len;
            return j;
        }
        j += len; // skip over it
    }
    *flen = 0; /*****/
    return 0;
}

// Find start date of certificate validity period
int X509_find_start_date(octad *c, int start)
{
    int j, len;
    j = start;

    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len);

    len = getalen(UTC, c->val, j);
    if (len < 0) 
    {  // could be generalised time 
        len = getalen(GTM, c->val, j);
        if (len<0) return 0;
        j += skip(len);
        j += 2; // skip century
    }
    else j += skip(len);
    return j;
}

// Find expiry date of certificate validity period
int X509_find_expiry_date(octad *c, int start)
{
    int j, len;
    j = start;

    len = getalen(SEQ, c->val, j);
    if (len < 0) return 0;
    j += skip(len);

    len = getalen(UTC, c->val, j);
    if (len < 0) 
    {
        len = getalen(GTM,c->val,j);
        if (len<0) return 0;
    }
    j += skip(len) + len;

    len = getalen(UTC, c->val, j);
    if (len < 0) 
    {
        len = getalen(GTM, c->val,j);
        if (len<0) return 0;
        j+=skip(len);
        j+=2; // skip century
    }
    else j += skip(len);

    return j;
}

int X509_find_extensions(octad *c)
{
    int j, len;
    j=X509_find_subject(c);

    len = getalen(SEQ, c->val, j);
    if (len<0) return 0;
    j += skip(len)+len; // skip subject

    len = getalen(SEQ, c->val, j);
    if (len<0) return 0;
    j += skip(len)+len; // skip public key

    if (j>=c->len) return 0;
    return j;
}

int X509_find_extension(octad *c, octad *SOID, int start, int *flen)
{
    int i, j, k, fin, len, tlen, nj;
    char foid[50];  /*****/
    octad FOID = {0, sizeof(foid), foid};

    j = start;

    tlen = getalen(EXT, c->val, j);
    if (tlen < 0) return 0;
    j += skip(tlen);

    tlen = getalen(SEQ, c->val, j);
    if (tlen < 0) return 0;
    j += skip(tlen);

    for (k = j; j < k + tlen;)
    {
        // search for Owner OID
        len = getalen(SEQ, c->val, j);
        if (len < 0) return 0;
        j += skip(len);  nj=j+len;
        len = getalen(OID, c->val, j);
        if (len < 0) return 0;
        j += skip(len);
        fin = j + len; // extract OID
        FOID.len = len;
        for (i = 0; j < fin; j++)
            FOID.val[i++] = c->val[j];
        if (OCT_compare(&FOID, SOID))
        {
            // if its the right one return
            *flen = nj-j;
            return j;
        }
        j = nj; // skip over this extension
    }
    *flen = 0; /*****/
    return 0;
}

// return 1 if name found, else 0, where name is URL
// input cert, and pointer to SAN extension
// Takes wild-card into consideration
int X509_find_alt_name(octad *c,int start,char *name)
{
    int i,j,len,k,m,tlen,cmp,tag;

    if (start==0) return 0;
    j=start;
    tlen = getalen(OCT, c->val, j);
    if (tlen < 0) return 0;
    j += skip(tlen);

    tlen = getalen(SEQ, c->val, j);
    if (tlen < 0) return 0;
    j += skip(tlen);  
    
    for (k=j;j<k+tlen;)
    {
        tag=c->val[j]; tag&=0xff;
        len = getalen(ANY, c->val, j);  
        if (len < 0) return 0;
        j += skip(len);               // ?? If its not dns, skip over it j+=len
        if (tag!=DNS)
        { // only interested in URLs
            j+=len;
            continue;
        }
        cmp=1; m=0;
        if (c->val[j]=='*')
        { // wildcard
            j++; len--; // skip over *
            while (name[m]!='.' && name[m]!=0)  // advance to first .
                m++;
        }
        for (i=0;i<len;i++)
        {
            if (name[m]==0)
            { // name has ended before comparison completed
                cmp=0;
                j++;
                continue;
            }
            if (c->val[j++]!=name[m++])  // mismatch
                cmp=0;
        }
        if (name[m]!=0) cmp=0; // name should have ended
        if (cmp) return 1;
    }
    return 0;
}


