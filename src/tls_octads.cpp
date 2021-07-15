//
// Safe octad handling in C
// octad buffers don't overflow - they truncate
//

#include "tls_octads.h"
//#include <stdio.h>

/* appends integer x of length len bytes to octad */
void OCT_append_int(octad *y, unsigned int x, int len)
{
    int i, n;
    n = y->len + len;
    if (n > y->max || len <= 0) 
    {
//        printf("1. ************************** Octad Problem!\n");
        return;
    }
    for (i = y->len; i < n; i++) y->val[i] = 0;
    y->len = n;

    i = y->len;
    while (x > 0 && i > 0)
    {
        i--;
        y->val[i] = x % 256;
        x /= 256;
    }
}

/* appends one octad to another */
void OCT_append_octad(octad *y, octad *x)
{
    /* y=y || x */
    int i, j;
    if (x == NULL) return;

    for (i = 0; i < x->len; i++)
    {
        j = y->len + i;
        if (j >= y->max)
        {
            y->len = y->max;
 //           printf("2. ************************** Octad Problem!\n");
            return;
        }
        y->val[j] = x->val[i];
    }
    y->len += x->len;
}

/* compare 2 octads
 * If x==y return TRUE, else return FALSE */

bool OCT_compare(octad *x, octad *y)
{
    int i,res=0;
    if (x->len != y->len) return false;
    
    for (i = 0; i < x->len; i++)
    {
        res |= (int)(x->val[i] ^ y->val[i]);
    }
    if (res==0) return true;
    return false;
}

/* Shift octad to the left by n bytes. Leftmost bytes disappear  */
void OCT_shift_left(octad *x, int n)
{
    int i;
    if (n >= x->len)
    {
        x->len = 0;
        return;
    }
    x->len -= n;
    for (i = 0; i < x->len; i++)
        x->val[i] = x->val[i + n];
}

/* Kill an octad string - Zeroise it for security */
void OCT_kill(octad *w)
{
    int i;
    for (i = 0; i < w->max; i++) w->val[i] = 0;
    w->len = 0;
}

static int char2int(char input)
{
    if (input >= '0' && input <= '9')
        return input - '0';
    if (input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if (input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    return 0;
}

/* Convert to octad from a hex string */
void OCT_from_hex(octad *dst, char *src)
{
    int i = 0;
    int j = 0;
    OCT_kill(dst);
    while (src[j] != 0 && i<dst->max)
    {
        dst->val[i++] = char2int(src[j]) * 16 + char2int(src[j + 1]);
        j += 2;
    }
    dst->len = i;
//    if (dst->len>=dst->max)
//        printf("3. ************************** Octad Problem!\n");
}

/* Appends C string to an octad - truncates if no room  */
void OCT_append_string(octad *y, char *s)
{
    int i, j;
    i = y->len;
    j = 0;
    while (s[j] != 0 && i < y->max)
    {
        y->val[i] = s[j];
        y->len++;
        i++;
        j++;
    }
 //   if (y->len>=y->max)
 //       printf("4. ************************** Octad Problem!\n");
}

/* Append byte to octad rep times */
void OCT_append_byte(octad *y, int ch, int rep)
{
    int i, j;
    i = y->len;
    for (j = 0; j < rep && i < y->max; j++)
    {
        y->val[i] = ch;
        y->len++;
        i++;
    }
//    if (y->len>=y->max)
//        printf("5. ************************** Octad Problem!\n");
}

/* Append byte array to octad - truncates if no room */
void OCT_append_bytes(octad *y, char *b, int len)
{
    int i, j;
    i = y->len;
    for (j = 0; j < len && i < y->max; j++)
    {
        y->val[i] = b[j];
        y->len++;
        i++;
    }
//    if (y->len>=y->max)
//        printf("6. ************************** Octad Problem!\n");
}

/* Convert to octad from a base64 string */
void OCT_from_base64(octad *w, char *b)
{
    int i, j, k, pads, len;// = (int)strlen(b);
    int c, ch[4], ptr[3];
    j = k = 0;

    len=0;
    while (b[len]!=0) len++;

    while (j < len && k < w->max)
    {
        pads = 0;
        for (i = 0; i < 4; i++)
        {
            c = 80 + b[j++];
            if (c <= 112) continue; /* ignore white space */
            if (c > 144 && c < 171) c -= 145;
            if (c > 176 && c < 203) c -= 151;
            if (c > 127 && c < 138) c -= 76;
            if (c == 123) c = 62;
            if (c == 127) c = 63;
            if (c == 141)
            {
                pads++;    /* ignore pads '=' */
                continue;
            }
            ch[i] = c;
        }
        ptr[0] = (ch[0] << 2) | (ch[1] >> 4);
        ptr[1] = (ch[1] << 4) | (ch[2] >> 2);
        ptr[2] = (ch[2] << 6) | ch[3];
        for (i = 0; i < 3 - pads && k < w->max; i++)
        {
            /* don't put in leading zeros */
            w->val[k++] = ptr[i];
        }

    }
    w->len = k;
}

/* reverse bytes. Useful if dealing with those unpleasant little-endian people */
void OCT_reverse(octad *w)
{
    int i;
    unsigned char ch;
    for (i = 0; i < w->len/2; i++) { 
        ch = w->val[i]; 
        w->val[i] = w->val[w->len - i - 1]; 
        w->val[w->len - i - 1] = ch; 
    } 
}

/* copy an octad string - truncates if no room */
void OCT_copy(octad *y, octad *x)
{
    int i;
    OCT_kill(y);
    y->len = x->len;
    if (y->len > y->max) 
    {
//        printf("7. ************************** Octad Problem!\n");
        y->len = y->max;
    }
    for (i = 0; i < y->len; i++)
        y->val[i] = x->val[i];
}

// Output octad to a zero-terminated C string, in hex
// output truncates after max chars, returns false if truncation occurs
bool OCT_output_hex(octad *O,int max,char *s)
{
    int i,j,t,b;
    bool rtn=true;
    unsigned char ch;
    for (i=j=0; i < O->len; i++)
    {
        ch = (unsigned char)O->val[i];
        t=ch>>4;
        if (t<10)
            s[j++]='0'+t;
        else
            s[j++]='A'+(t-10);

        b=ch&0xF;
        if (b<10)
            s[j++]='0'+b;
        else
            s[j++]='A'+(b-10);

        if (j>=max)
        {
            rtn=false;
            break;
        }
    }
    s[j]=0;
    return rtn;
}

// Output octad to a zero-terminated C string, as an Ascii string
// output truncates after max chars, returns false if truncation occurs
bool OCT_output_string(octad *O,int max,char *s)
{
    int i,j;
    bool rtn=true;
    unsigned char ch;
    for (i=j=0; i < O->len; i++)
    {
        ch = (unsigned char)O->val[i];
        s[j++]=ch;
        if (ch==0) return rtn;
        if (j>=max)
        {
            rtn=false;
            break;
        }
    }
    s[j]=0;
    return rtn;
}

void OCT_truncate(octad *O,int n)
{
    if (n<O->len)
        O->len=n;
}

/* Convert an octad string to base64 string */
void OCT_output_base64(octad *O,int max,char *b)
{
    int i, j, k, rem, last;
    int c, ch[4];
    bool rtn=true;
    unsigned char ptr[3];
    rem = O->len % 3;
    j = k = 0;
    last = 4;
    while (j < O->len)
    {
        for (i = 0; i < 3; i++)
        {
            if (j < O->len) ptr[i] = O->val[j++];
            else
            {
                ptr[i] = 0;
                last--;
            }
        }
        ch[0] = (ptr[0] >> 2) & 0x3f;
        ch[1] = ((ptr[0] << 4) | (ptr[1] >> 4)) & 0x3f;
        ch[2] = ((ptr[1] << 2) | (ptr[2] >> 6)) & 0x3f;
        ch[3] = ptr[2] & 0x3f;
        for (i = 0; i < last; i++)
        {
            c = ch[i];
            if (c < 26) c += 65;
            if (c >= 26 && c < 52) c += 71;
            if (c >= 52 && c < 62) c -= 4;
            if (c == 62) c = '+';
            if (c == 63) c = '/';
            b[k++] = c;
        }
        if (k>=max)
        {
            rtn=false;
            break;
        }
    }
    if (k<max && rem>0) for (i = rem; i < 3; i++) b[k++] = '=';
    b[k] = '\0'; /* dangerous! */
}
