#include <fstream>
#include "core.h"
#include "x509.h"

using namespace core;
using namespace std;

static void print_out(char *des, octet *c, int index, int len)
{
    int i;
    printf("%s [", des);
    for (i = 0; i < len; i++)
        printf("%c", c->val[index + i]);
    printf("]\n");
}

// given root issuer and public key type of signature, search through root CAs and return root public key
bool FIND_ROOT_CA(octet* ISSUER,pktype st,octet *PUBKEY)
{
    char sc[8192];
    octet SC={0,sizeof(sc),sc};
    char c[8192];
    octet C={0,sizeof(c),c};
    char ca[50];
    octet CA={0,sizeof(ca),ca};
    char owner[50];
    octet OWNER={0,sizeof(owner),owner};
    char b[8192];
    ifstream file("ca-certificates.crt");

    if (file.is_open()) {
        string line;
        for (;;)
        {
            int i=0;
            if (!getline(file, line)) break;
            for (;;)
            {
                getline(file,line);
                if (line.c_str()[0]=='-') break;
                for (int j=0;j<64;j++)
                    b[i++]=line.c_str()[j];
                b[i]=0;
            }
            OCT_frombase64(&SC,b);

            int c = X509_extract_cert(&SC, &C);

            int ic = X509_find_issuer(&C);
            int alen,ac=X509_find_entity_property(&C, &X509_MN, ic, &alen);
            OCT_clear(&OWNER);
            OCT_jbytes(&OWNER,&C.val[ac],alen);

            if (OCT_comp(&OWNER,ISSUER))
            {
                pktype pt = X509_extract_public_key(&C, PUBKEY);
                if (st.type==pt.type && st.curve==pt.curve) 
                {
                    file.close();   
                    return true;
                }
            }
        }
        file.close();   
    }
    return false;
}

int main()
{
    char ca[50];
    octet CA={0,sizeof(ca),ca};
    char pubkey[512];
    octet PUBKEY={0,sizeof(pubkey),pubkey};

    ifstream file("ca-certificates.crt");

    OCT_jstring(&CA,(char *)"Baltimore CyberTrust Root");
    pktype pa;
    pa.type=X509_RSA;
    pa.curve=2048;

    if (FIND_ROOT_CA(&CA,pa,&PUBKEY)) {
        printf("Public Key= "); OCT_output(&PUBKEY);
        printf("type= %d, hash= %d, curve/len= %d\n",pa.type,pa.hash,pa.curve); 
    } else {
        printf("Root CA not found\n");
    }
}
