#!/usr/bin/env python3

#
# Copyright (c) 2012-2020 MIRACL UK Ltd.
#
# This file is part of MIRACL Core
# (see https://github.com/miracl/core).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import sys

deltext="rm"
copytext="cp"
slashtext="/"
if sys.platform.startswith("win") :
    deltext="del"
    copytext=">NUL copy"
    slashtext="\\"

def inline_mul1(N,base)  :
    str=""
    str+="\tt=(dchunk)a[0]*b[0]; c[0]=(chunk)t & BMASK_XXX; t=t>>BASEBITS_XXX;\n"

    for i in range(1,N) :
        k=0;
        str+="\tt=t"
        while (k<=i) :
            str+="+(dchunk)a[{}]*b[{}]".format(k,i-k)
            k+=1
        str+="; c[{}]=(chunk)t & BMASK_XXX; ".format(i)
        str+="t=t>>BASEBITS_XXX;\n"

    for i in range(N,2*N-1) :
        k=i-(N-1)
        str+="\tt=t"
        while (k<=N-1) :
            str+="+(dchunk)a[{}]*b[{}]".format(k,i-k)
            k+=1
        str+="; c[{}]=(chunk)t & BMASK_XXX; ".format(i)
        str+="t=t>>BASEBITS_XXX;\n"

    str+="\tc[{}]=(chunk)t;\n".format(2*N-1)

    return str.replace("XXX",base)

def inline_mul2(N,base)  :
    str=""
    for i in range(0,N) :
        str+="\td[{}]=(dchunk)a[{}]*b[{}];\n".format(i, i, i)
    str+="\n\ts=d[0];\n\tt = s; c[0]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX;\n"
    for k in range(1,N) :
        str+="\ts+=d[{}]; t=co+s ".format(k)
        for i in range(k,int(k/2),-1) :
            str+="+(dchunk)(a[{}]-a[{}])*(b[{}]-b[{}])".format(i,k - i, k - i, i)
        str+="; c[{}]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n".format(k)
    str+="\n"
    for k in range(N,2 * N - 1) :
        str+="\ts-=d[{}]; t=co+s ".format(k - N)
        for i in range(N-1,int(k/2),-1) :
            str+="+(dchunk)(a[{}]-a[{}])*(b[{}]-b[{}])".format(i, k - i, k - i, i)
        str+="; c[{}]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n".format(k)

    str+="\tc[{}]=(chunk)co;\n".format(2 * N - 1)
    return str.replace("XXX",base)

def inline_sqr(N,base) :
    str=""
    str+="\n\tt=(dchunk)a[0]*a[0]; c[0]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX;\n"

    for k in range(1,N) :
        str+="\tt= "
        for i in range(k,int(k/2),-1) :
            str+="+(dchunk)a[{}]*a[{}]".format(i, k - i)
        str+="; t+=t; t+=co;"
        if k % 2 == 0 :
            str+=" t+=(dchunk)a[{}]*a[{}];".format(int(k/2), int(k/2))
        str+=" c[{}]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n".format(k)
    str+="\n"

    for k in range(N,2*N-2) :
        str+="\tt= "
        for i in range(N-1,int(k/2),-1) :
            str+="+(dchunk)a[{}]*a[{}]".format(i, k - i)
        str+="; t+=t; t+=co;"
        if k % 2 == 0 :
            str+=" t+=(dchunk)a[{}]*a[{}];".format(int(k/2),int(k/2))
        str+=" c[{}]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n".format(k)

    str+="\tt=co; t+=(dchunk)a[{}]*a[{}]; c[{}]=(chunk)t&BMASK_XXX; co=t>>BASEBITS_XXX; \n ".format(N-1,N-1,2*N-2)

    str+="\tc[{}]=(chunk)co;\n".format(2 * N - 1)
    return str.replace("XXX",base)

def inline_redc2(N,base) :
    str=""
    str+="\tt=d[0]; v[0]=((chunk)t*MC)&BMASK_XXX; t+=(dchunk)v[0]*md[0];  s=0; c=(t>>BASEBITS_XXX);\n\n"

    for k in range(1,N) :
        str+="\tt=d[{}]+c+s+(dchunk)v[0]*md[{}]".format(k, k)
        for i in range(k-1,int(k/2),-1) :
            str+="+(dchunk)(v[{}]-v[{}])*(md[{}]-md[{}])".format(k - i, i, i, k - i)
        str+="; v[{}]=((chunk)t*MC)&BMASK_XXX; t+=(dchunk)v[{}]*md[0]; ".format(k, k)
        str+=" dd[{}]=(dchunk)v[{}]*md[{}]; s+=dd[{}]; c=(t>>BASEBITS_XXX); \n".format(k, k, k, k)

    str+="\n"
    for k in range(N,2*N-1) :
        str+="\tt=d[{}]+c+s".format(k)
        for i in range(N-1,int(k/2),-1) :
            str+="+(dchunk)(v[{}]-v[{}])*(md[{}]-md[{}])".format(k - i, i, i, k - i)
        str+="; a[{}]=(chunk)t&BMASK_XXX;  s-=dd[{}]; c=(t>>BASEBITS_XXX); \n".format(k - N, k - N + 1)

    str+="\ta[{}]=d[{}]+((chunk)c&BMASK_XXX);\n".format(N-1,2*N-1)
    return str.replace("XXX",base)

def inline_redc1(N,base) :
    str=""

    str+="\tt = d[0];\n"
    str+="\tv[0] = ((chunk)t * MC)&BMASK_XXX;\n"
    str+="\tt += (dchunk)v[0] * md[0];\n"
    str+="\tt = (t >> BASEBITS_XXX) + d[1];\n"

    for i in range(1,N) :
        k=1
        str+="\tt += (dchunk)v[0] * md[{}] ".format(i)
        while k<i :
            str+="+ (dchunk)v[{}]*md[{}]".format(k,i-k)
            k+=1
        str+="; v[{}] = ((chunk)t * MC)&BMASK_XXX; ".format(i)
        str+="t += (dchunk)v[{}] * md[0]; ".format(i)
        str+="t = (t >> BASEBITS_XXX) + d[{}];\n".format(i+1)

    for i in range(N,2*N-1) :
        k=i-(N-1)
        str+="\tt=t "
        while k<=N-1 :
            str+="+ (dchunk)v[{}]*md[{}] ".format(k,i-k)
            k+=1
        str+="; a[{}] = (chunk)t & BMASK_XXX; ".format(i-N)
        str+="t = (t >> BASEBITS_XXX) + d[{}];\n".format(i+1)

    str+="\ta[{}] = (chunk)t & BMASK_XXX;\n".format(N-1)
    return str.replace("XXX",base)



def replace(namefile,oldtext,newtext):
    f = open(namefile,'r')
    filedata = f.read()
    f.close()

    newdata = filedata.replace(oldtext,newtext)

    f = open(namefile,'w')
    f.write(newdata)
    f.close()


def rsaset(tb,tff,base,ml) :
    itb=int(tb)
    inb=int(itb/8)
    nb=str(inb)

    ib=int(base)
    inb=int(nb)

    nlen=(1+((8*inb-1)//ib))

    bd="B"+tb+"_"+base
    fnameh="config_big_"+bd+".h"
    os.system(copytext+" config_big.h "+fnameh)
    replace(fnameh,"XXX",bd)
    replace(fnameh,"@NB@",nb)
    replace(fnameh,"@BASE@",base)

    fnameh="config_ff_"+tff+".h"
    os.system(copytext+" config_ff.h "+fnameh)
    replace(fnameh,"XXX",bd)
    replace(fnameh,"WWW",tff)
    replace(fnameh,"@ML@",ml)

    fnamec="big_"+bd+".cpp"
    fnameh="big_"+bd+".h"

    os.system(copytext+" big.cpp "+fnamec)
    os.system(copytext+" big.h "+fnameh)

    replace(fnamec,"XXX",bd)
    replace(fnameh,"XXX",bd)

    replace(fnamec,"INLINE_MUL1",inline_mul1(nlen,bd))
    replace(fnamec,"INLINE_MUL2",inline_mul2(nlen,bd))
    replace(fnamec,"INLINE_SQR",inline_sqr(nlen,bd))
    replace(fnamec,"INLINE_REDC1",inline_redc1(nlen,bd))
    replace(fnamec,"INLINE_REDC2",inline_redc2(nlen,bd))


    fnamec="ff_"+tff+".cpp"
    fnameh="ff_"+tff+".h"

    os.system(copytext+" ff.cpp "+fnamec)
    os.system(copytext+" ff.h "+fnameh)

    replace(fnamec,"WWW",tff)
    replace(fnamec,"XXX",bd)
    replace(fnameh,"WWW",tff)
    replace(fnameh,"XXX",bd)

    fnamec="rsa_"+tff+".cpp"
    fnameh="rsa_"+tff+".h"

    os.system(copytext+" rsa.cpp "+fnamec)
    os.system(copytext+" rsa.h "+fnameh)

    replace(fnamec,"WWW",tff)
    replace(fnamec,"XXX",bd)
    replace(fnameh,"WWW",tff)
    replace(fnameh,"XXX",bd)

#    replace("testrsa.ino","XXX",tff)

def curveset(nbt,tf,tc,base,m8,rz,mt,qi,ct,ca,pf,stw,sx,g2,ab,cs) :
    inbt=int(nbt)
    itb=int(inbt+(8-inbt%8)%8)
    inb=int(itb/8)
    tb=str(itb)
    nb=str(inb)

    bd="B"+tb+"_"+base
    fnameh="config_big_"+bd+".h"
    os.system(copytext+" config_big.h "+fnameh)
    replace(fnameh,"XXX",bd)
    replace(fnameh,"@NB@",nb)
    replace(fnameh,"@BASE@",base)

    fnameh="config_field_"+tf+".h"
    os.system(copytext+" config_field.h "+fnameh)
    replace(fnameh,"XXX",bd)
    replace(fnameh,"YYY",tf)
    replace(fnameh,"@NBT@",nbt)
    replace(fnameh,"@M8@",m8)
    replace(fnameh,"@MT@",mt)
    hc="0"
    hc2="0"
# Get Hash-to-Curve Z for G1 and G2

    if isinstance(rz,list) :
        if len(rz)==2 :     # Z followed by SSWU isogeny degree
            replace(fnameh,"@RZ@",rz[0])
            replace(fnameh,"@RZ2A@","0")
            replace(fnameh,"@RZ2B@","0")
            hc=rz[1]
        if len(rz)==3 :     # Z for G1 followed by Z for G2 (for SVDW)
            replace(fnameh,"@RZ@",rz[0])
            replace(fnameh,"@RZ2A@",rz[1])
            replace(fnameh,"@RZ2B@",rz[2])
        if len(rz)==5 :     # Z for G1, Z for G2, SSWU isogeny degree for G1, SSWU isogeny degree for G2
            replace(fnameh,"@RZ@",rz[0])
            replace(fnameh,"@RZ2A@",rz[1])
            replace(fnameh,"@RZ2B@",rz[2])
            hc=rz[3]
            hc2=rz[4]
    else :
        replace(fnameh,"@RZ@",rz)   # just Z for SSWU, or indicates RFC7748 or Generic for Elligator
        replace(fnameh,"@RZ2A@","0")
        replace(fnameh,"@RZ2B@","0")

    itw=int(qi)%10
    replace(fnameh,"@QI@",str(itw))
    if int(qi)//10 > 0 :
        replace(fnameh,"@TW@","POSITOWER")
    else :
        replace(fnameh,"@TW@","NEGATOWER")

    ib=int(base)
    inb=int(nb)
    inbt=int(nbt)
    nlen=(1+((8*inb-1)//ib))
    sh=ib*nlen-inbt


    if sh > 14 :
        sh=14
    replace(fnameh,"@SH@",str(sh))

    fnameh="config_curve_"+tc+".h"
    os.system(copytext+" config_curve.h "+fnameh)
    replace(fnameh,"XXX",bd)
    replace(fnameh,"YYY",tf)
    replace(fnameh,"ZZZ",tc)
    replace(fnameh,"@CT@",ct)
    replace(fnameh,"@CA@",ca)
    replace(fnameh,"@PF@",pf)

    replace(fnameh,"@ST@",stw)
    replace(fnameh,"@SX@",sx)
    replace(fnameh,"@CS@",cs)
    replace(fnameh,"@AB@",ab)
    replace(fnameh,"@G2@",g2)

    replace(fnameh,"@HC@",hc) 
    replace(fnameh,"@HC2@",hc2) 

    fnamec="big_"+bd+".cpp"
    fnameh="big_"+bd+".h"

    os.system(copytext+" big.cpp "+fnamec)
    os.system(copytext+" big.h "+fnameh)

    replace(fnamec,"XXX",bd)
    replace(fnameh,"XXX",bd)

    replace(fnamec,"INLINE_MUL1",inline_mul1(nlen,bd))
    replace(fnamec,"INLINE_MUL2",inline_mul2(nlen,bd))
    replace(fnamec,"INLINE_SQR",inline_sqr(nlen,bd))
    replace(fnamec,"INLINE_REDC1",inline_redc1(nlen,bd))
    replace(fnamec,"INLINE_REDC2",inline_redc2(nlen,bd))


    fnamec="fp_"+tf+".cpp"
    fnameh="fp_"+tf+".h"

    os.system(copytext+" fp.cpp "+fnamec)
    os.system(copytext+" fp.h "+fnameh)

    replace(fnamec,"YYY",tf)
    replace(fnamec,"XXX",bd)
    replace(fnameh,"YYY",tf)
    replace(fnameh,"XXX",bd)

    fnamec="ecp_"+tc+".cpp"
    fnameh="ecp_"+tc+".h"

    os.system(copytext+" ecp.cpp "+fnamec)
    os.system(copytext+" ecp.h "+fnameh)

    replace(fnamec,"ZZZ",tc)
    replace(fnamec,"YYY",tf)
    replace(fnamec,"XXX",bd)
    replace(fnameh,"ZZZ",tc)
    replace(fnameh,"YYY",tf)
    replace(fnameh,"XXX",bd)

    fnamec="ecdh_"+tc+".cpp"
    fnameh="ecdh_"+tc+".h"

    os.system(copytext+" ecdh.cpp "+fnamec)
    os.system(copytext+" ecdh.h "+fnameh)

    replace(fnamec,"ZZZ",tc)
    replace(fnamec,"YYY",tf)
    replace(fnamec,"XXX",bd)
    replace(fnameh,"ZZZ",tc)
    replace(fnameh,"YYY",tf)
    replace(fnameh,"XXX",bd)

    fnamec="hpke_"+tc+".cpp"
    fnameh="hpke_"+tc+".h"

    os.system(copytext+" hpke.cpp "+fnamec)
    os.system(copytext+" hpke.h "+fnameh)

    replace(fnamec,"ZZZ",tc)
    replace(fnameh,"ZZZ",tc)

    if pf != "NOT_PF" :
        fnamec="fp2_"+tf+".cpp"
        fnameh="fp2_"+tf+".h"

        os.system(copytext+" fp2.cpp "+fnamec)
        os.system(copytext+" fp2.h "+fnameh)
        replace(fnamec,"YYY",tf)
        replace(fnamec,"XXX",bd)
        replace(fnameh,"YYY",tf)
        replace(fnameh,"XXX",bd)

        fnamec="fp4_"+tf+".cpp"
        fnameh="fp4_"+tf+".h"

        os.system(copytext+" fp4.cpp "+fnamec)
        os.system(copytext+" fp4.h "+fnameh)
        replace(fnamec,"YYY",tf)
        replace(fnamec,"XXX",bd)
        replace(fnamec,"ZZZ",tc)
        replace(fnameh,"YYY",tf)
        replace(fnameh,"XXX",bd)
        replace(fnameh,"ZZZ",tc)

        if pf == "BN_CURVE" or pf == "BLS12_CURVE" :
            fnamec="fp12_"+tf+".cpp"
            fnameh="fp12_"+tf+".h"

            os.system(copytext+" fp12.cpp "+fnamec)
            os.system(copytext+" fp12.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="ecp2_"+tc+".cpp"
            fnameh="ecp2_"+tc+".h"

            os.system(copytext+" ecp2.cpp "+fnamec)
            os.system(copytext+" ecp2.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="pair_"+tc+".cpp"
            fnameh="pair_"+tc+".h"

            os.system(copytext+" pair.cpp "+fnamec)
            os.system(copytext+" pair.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="mpin_"+tc+".cpp"
            fnameh="mpin_"+tc+".h"

            os.system(copytext+" mpin.cpp "+fnamec)
            os.system(copytext+" mpin.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="bls_"+tc+".cpp"
            fnameh="bls_"+tc+".h"

            os.system(copytext+" bls.cpp "+fnamec)
            os.system(copytext+" bls.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

        if pf == "BLS24_CURVE" :
            fnamec="fp8_"+tf+".cpp"
            fnameh="fp8_"+tf+".h"

            os.system(copytext+" fp8.cpp "+fnamec)
            os.system(copytext+" fp8.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="fp24_"+tf+".cpp"
            fnameh="fp24_"+tf+".h"

            os.system(copytext+" fp24.cpp "+fnamec)
            os.system(copytext+" fp24.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="ecp4_"+tc+".cpp"
            fnameh="ecp4_"+tc+".h"

            os.system(copytext+" ecp4.cpp "+fnamec)
            os.system(copytext+" ecp4.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="pair4_"+tc+".cpp"
            fnameh="pair4_"+tc+".h"

            os.system(copytext+" pair4.cpp "+fnamec)
            os.system(copytext+" pair4.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="mpin192_"+tc+".cpp"
            fnameh="mpin192_"+tc+".h"

            os.system(copytext+" mpin192.cpp "+fnamec)
            os.system(copytext+" mpin192.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="bls192_"+tc+".cpp"
            fnameh="bls192_"+tc+".h"

            os.system(copytext+" bls192.cpp "+fnamec)
            os.system(copytext+" bls192.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

        if pf == "BLS48_CURVE" :

            fnamec="fp8_"+tf+".cpp"
            fnameh="fp8_"+tf+".h"

            os.system(copytext+" fp8.cpp "+fnamec)
            os.system(copytext+" fp8.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="ecp8_"+tc+".cpp"
            fnameh="ecp8_"+tc+".h"

            os.system(copytext+" ecp8.cpp "+fnamec)
            os.system(copytext+" ecp8.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="fp16_"+tf+".cpp"
            fnameh="fp16_"+tf+".h"

            os.system(copytext+" fp16.cpp "+fnamec)
            os.system(copytext+" fp16.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="fp48_"+tf+".cpp"
            fnameh="fp48_"+tf+".h"

            os.system(copytext+" fp48.cpp "+fnamec)
            os.system(copytext+" fp48.h "+fnameh)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnamec,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
            replace(fnameh,"ZZZ",tc)

            fnamec="pair8_"+tc+".cpp"
            fnameh="pair8_"+tc+".h"

            os.system(copytext+" pair8.cpp "+fnamec)
            os.system(copytext+" pair8.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="mpin256_"+tc+".cpp"
            fnameh="mpin256_"+tc+".h"

            os.system(copytext+" mpin256.cpp "+fnamec)
            os.system(copytext+" mpin256.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)

            fnamec="bls256_"+tc+".cpp"
            fnameh="bls256_"+tc+".h"

            os.system(copytext+" bls256.cpp "+fnamec)
            os.system(copytext+" bls256.h "+fnameh)
            replace(fnamec,"ZZZ",tc)
            replace(fnamec,"YYY",tf)
            replace(fnamec,"XXX",bd)
            replace(fnameh,"ZZZ",tc)
            replace(fnameh,"YYY",tf)
            replace(fnameh,"XXX",bd)
#        replace("testbls.ino","XXX",tc)
#        replace("timepbc.ino","XXX",tc)
#    else :
#        replace("testecc.ino","XXX",tc)
#        replace("timeecc.ino","XXX",tc)
#        replace("timeecc.ino","YYY",tf)


replace("arch.h","@WL@","32")
print("Elliptic Curves")
print("1. ED25519")
print("2. C25519")
print("3. NIST256")
print("4. BRAINPOOL")
print("5. ANSSI")
print("6. HIFIVE")
print("7. GOLDILOCKS")
print("8. NIST384")
print("9. C41417")
print("10. NIST521\n")
print("11. NUMS256W")
print("12. NUMS256E")
print("13. NUMS384W")
print("14. NUMS384E")
print("15. NUMS512W")
print("16. NUMS512E")
print("17. SECP256K1")
print("18. SM2")
print("19. C13318")
print("20. JUBJUB")
print("21. X448")
print("22. SECP160R1")
print("23. C1174")
print("24. C1665")
print("25. Million Dollar Curve")
print("26. TWEEDLEDUM")
print("27. TWEEDLEDEE\n")


print("Pairing-Friendly Elliptic Curves")
print("28. BN254")
print("29. BN254CX")
print("30. BLS12383")
print("31. BLS12381")
print("32. FP256BN")
print("33. FP512BN")
print("34. BLS12443")
print("35. BLS12461")
print("36. BN462")
print("37. BLS24479")
print("38. BLS48556")
print("39. BLS48581")
print("40. BLS48286\n")

print("RSA")
print("41. RSA2048")
print("42. RSA3072")
print("43. RSA4096")
print("44. NewHope\n")

selection=[]
ptr=0
max=45

def selected(selection,sel,len) :
    for i in range(0,len):
        if sel==selection[i] :
            return True
    return False


curve_selected=False
pfcurve_selected=False
rsa_selected=False
nhs_selected=False

while ptr<max:
    x=int(input("Choose a Scheme to support - 0 to finish: "))
    if x == 0:
        break
#    print("Choice= ",x)
    already=False
    for i in range(0,ptr):
        if x==selection[i]:
            already=True
            break
    if already:
        continue

    selection.append(x)
    ptr=ptr+1

# curveset(modulus_bits,field,curve,bits_in_base,modulus_mod_8,Z,modulus_type,curve_type,pairing_friendly,sextic twist,sign of x,g2_table size,ate bits,curve security)
# for each curve give names for field and curve. In many cases the latter two will be the same.
# modulus_bits is the bit length of the modulus, typically the same or slightly smaller than "big"
# Typically "field" describes the modulus, and "curve" is the common name for the elliptic curve
# Next give the number base used for 32 bit architecture, as n where the base is 2^n (note that these must be fixed for the same "big" name, if is ever re-used for another curve)
# m8 max m such that 2^m | modulus-1
# rz Z value for hash_to_point, If list G1 Z value is in [0], G2 Z value (=a+bz) is in [1], [2]
# modulus_type is NOT_SPECIAL, or PSEUDO_MERSENNE, or MONTGOMERY_Friendly, or GENERALISED_MERSENNE (supported for GOLDILOCKS only)
# i for Fp2 QNR 2^i+sqrt(-1) (relevant for PFCs only, else =0). Or QNR over Fp if p=1 mod 8
# curve_type is WEIERSTRASS, EDWARDS or MONTGOMERY
# Curve A parameter
# pairing_friendly is BN_CURVE, BLS_CURVE or NOT_PF (if not pairing friendly)
# if pairing friendly. M or D type twist, and sign of the family parameter x
# g2_table size is number of entries in precomputed table
# ate bits is number of bits in Ate parameter (from romgen program)
# curve security is AES equiavlent, rounded up.

    if x==1:
        curveset("255","F25519","ED25519","29","2","1","PSEUDO_MERSENNE","0","EDWARDS","-1","NOT_PF","","","","","128")
        curve_selected=True
    if x==2:
        curveset("255","F25519","C25519","29","2","1","PSEUDO_MERSENNE","0","MONTGOMERY","486662","NOT_PF","","","","","128")
        curve_selected=True
    if x==3:
        curveset("256","NIST256","NIST256","28","1","-10","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True
    if x==4:
        curveset("256","BRAINPOOL","BRAINPOOL","28","1","-3","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True
    if x==5:
        curveset("256","ANSSI","ANSSI","28","1","-5","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True

    if x==6:
        curveset("336","HIFIVE","HIFIVE","29","2","1","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","192")
        curve_selected=True
    if x==7:
        curveset("448","GOLDILOCKS","GOLDILOCKS","29","1","0","GENERALISED_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","256")
        curve_selected=True
    if x==8:
        curveset("384","NIST384","NIST384","29","1","-12","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","192")
        curve_selected=True
    if x==9:
        curveset("414","C41417","C41417","29","1","1","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","256")
        curve_selected=True
    if x==10:
        curveset("521","NIST521","NIST521","28","1","-4","PSEUDO_MERSENNE","0","WEIERSTRASS","-3","NOT_PF","","","","","256")
        curve_selected=True

    if x==11:
        curveset("256","F256PMW","NUMS256W","28","1","7","PSEUDO_MERSENNE","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True
    if x==12:
        curveset("256","F256PME","NUMS256E","29","1","0","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","128")
        curve_selected=True
    if x==13:
        curveset("384","F384PM","NUMS384W","29","1","-4","PSEUDO_MERSENNE","0","WEIERSTRASS","-3","NOT_PF","","","","","192")
        curve_selected=True
    if x==14:
        curveset("384","F384PM","NUMS384E","29","1","0","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","192")
        curve_selected=True
    if x==15:
        curveset("512","F512PM","NUMS512W","29","1","-4","PSEUDO_MERSENNE","0","WEIERSTRASS","-3","NOT_PF","","","","","256")
        curve_selected=True
    if x==16:
        curveset("512","F512PM","NUMS512E","29","1","0","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","256")
        curve_selected=True

    if x==17:
#                                                       ,"1", for SVDW
# set for SSWU plus isogenies
        curveset("256","SECP256K1","SECP256K1","28","1",["-11","3"],"NOT_SPECIAL","0","WEIERSTRASS","0","NOT_PF","","","","","128")
        curve_selected=True

    if x==18:
        curveset("256","SM2","SM2","28","1","-9","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True

    if x==19:
        curveset("255","F25519","C13318","29","2","2","PSEUDO_MERSENNE","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True

    if x==20:
        curveset("255","JUBJUB","JUBJUB","29","32","1","NOT_SPECIAL","5","EDWARDS","-1","NOT_PF","","","","","128")
        curve_selected=True

    if x==21:
        curveset("448","GOLDILOCKS","X448","29","1","0","GENERALISED_MERSENNE","0","MONTGOMERY","156326","NOT_PF","","","","","256")
        curve_selected=True

    if x==22:
        curveset("160","SECP160R1","SECP160R1","29","1","3","NOT_SPECIAL","0","WEIERSTRASS","-3","NOT_PF","","","","","128")
        curve_selected=True

    if x==23:
        curveset("251","C1174","C1174","29","1","0","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","128")
        curve_selected=True

    if x==24:
        curveset("166","C1665","C1665","29","1","0","PSEUDO_MERSENNE","0","EDWARDS","1","NOT_PF","","","","","128")
        curve_selected=True

    if x==25:
        curveset("256","MDC","MDC","28","1","0","NOT_SPECIAL","0","EDWARDS","1","NOT_PF","","","","","128")
        curve_selected=True


    if x==26:
        curveset("255","TWEEDLEDUM","TWEEDLEDUM","29","33","1","NOT_SPECIAL","5","WEIERSTRASS","0","NOT_PF","","","","","128")
        curve_selected=True

    if x==27:
        curveset("255","TWEEDLEDEE","TWEEDLEDEE","29","34","1","NOT_SPECIAL","5","WEIERSTRASS","0","NOT_PF","","","","","128")
        curve_selected=True

    pf=28

    if x==pf+0:
        curveset("254","BN254","BN254","28","1",["-1","-1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BN_CURVE","D_TYPE","NEGATIVEX","71","66","128")
        pfcurve_selected=True
    if x==pf+1:
        curveset("254","BN254CX","BN254CX","28","1",["-1","-1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BN_CURVE","D_TYPE","NEGATIVEX","76","66","128")
        pfcurve_selected=True
    if x==pf+2:
        curveset("383","BLS12383","BLS12383","29","1",["1","1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS12_CURVE","M_TYPE","POSITIVEX","68","65","128")
        pfcurve_selected=True

    if x==pf+3:
#                                                      ["-3" ,"-1", "0"]  for SVDW
# set for SSWU plus isogenies
        curveset("381","BLS12381","BLS12381","29","1",["11","-2","-1","11","3"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS12_CURVE","M_TYPE","NEGATIVEX","69","65","128")
        pfcurve_selected=True

    if x==pf+4:
        curveset("256","FP256BN","FP256BN","28","1",["1","1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BN_CURVE","M_TYPE","NEGATIVEX","83","66","128")
        pfcurve_selected=True
    if x==pf+5:
        curveset("512","FP512BN","FP512BN","29","1",["1","1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BN_CURVE","M_TYPE","POSITIVEX","172","130","128")
        pfcurve_selected=True


    if x==pf+6:
        curveset("443","BLS12443","BLS12443","29","1",["-7","1","1","11","3"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS12_CURVE","M_TYPE","POSITIVEX","78","75","128")
        pfcurve_selected=True


# https://eprint.iacr.org/2017/334.pdf
    if x==pf+7:
        curveset("461","BLS12461","BLS12461","28","1",["1","4","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS12_CURVE","M_TYPE","NEGATIVEX","79","78","128")
        pfcurve_selected=True

    if x==pf+8:
        curveset("462","BN462","BN462","28","1",["1","1","0"],"NOT_SPECIAL","1","WEIERSTRASS","0","BN_CURVE","D_TYPE","POSITIVEX","125","118","128")   # was 0 M_TYPE
        pfcurve_selected=True
    if x==pf+9:
        curveset("479","BLS24479","BLS24479","29","1",["1","4","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS24_CURVE","M_TYPE","POSITIVEX","52","49","192")
        pfcurve_selected=True

    if x==pf+10:
        curveset("556","BLS48556","BLS48556","29","1",["-1","2","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS48_CURVE","M_TYPE","POSITIVEX","35","32","256")
        pfcurve_selected=True

    if x==pf+11:
        curveset("581","BLS48581","BLS48581","29","1",["2","2","0"],"NOT_SPECIAL","10","WEIERSTRASS","0","BLS48_CURVE","D_TYPE","NEGATIVEX","36","33","256")
        pfcurve_selected=True

    if x==pf+12:
        curveset("286","BLS48286","BLS48286","29","1",["1","1","0"],"NOT_SPECIAL","0","WEIERSTRASS","0","BLS48_CURVE","M_TYPE","POSITIVEX","20","17","128")
        pfcurve_selected=True

# rsaset(big,ring,big_length_bytes,bit_bits_in_base,multiplier)
# for each choice give distinct names for "big" and "ring".
# Typically "big" is the length in bits of the underlying big number type
# "ring" is the RSA modulus size = "big" times 2^m
# big_length_bytes is "big" divided by 8
# Next give the number base used for 32 bit architectures, as n where the base is 2^n
# multiplier is 2^m (see above)

# There are choices here, different ways of getting the same result, but some faster than others
# There are choices here, different ways of getting the same result, but some faster than others
    if x==pf+13:
        #256 is slower but may allow reuse of 256-bit BIGs used for elliptic curve
        #512 is faster.. but best is 1024
        #rsaset("1024","RSA2048","28","2")
        rsaset("512","RSA2048","29","4")
        #rsaset("256","RSA2048","29","8")
        rsa_selected=True
    if x==pf+14:
        rsaset("384","RSA3072","28","8")
        rsa_selected=True
    if x==pf+15:
        #rsaset("256","RSA4096","29","16")
        rsaset("512","RSA4096","29","8")
        rsa_selected=True

    if x==pf+16:
        nhs_selected=True

#    break;

os.system(deltext+" *.rs")
#os.system(deltext+" fast*.*")
os.system(deltext+" big.*")
os.system(deltext+" fp.*")
os.system(deltext+" ecp.*")
os.system(deltext+" ecdh.*")
os.system(deltext+" hpke.*")
os.system(deltext+" ff.*")
os.system(deltext+" rsa.*")
os.system(deltext+" config_big.h")
os.system(deltext+" config_field.h")
os.system(deltext+" config_curve.h")
os.system(deltext+" config_ff.h")
os.system(deltext+" fp2.*")
os.system(deltext+" fp4.*")
os.system(deltext+" fp8.*")
os.system(deltext+" fp16.*")

os.system(deltext+" fp12.*")
os.system(deltext+" fp24.*")
os.system(deltext+" fp48.*")

os.system(deltext+" ecp2.*")
os.system(deltext+" ecp4.*")
os.system(deltext+" ecp8.*")

os.system(deltext+" pair.*")
os.system(deltext+" mpin.*")
os.system(deltext+" bls.*")

os.system(deltext+" pair4.*")
os.system(deltext+" mpin192.*")
os.system(deltext+" bls192.*")

os.system(deltext+" pair8.*")
os.system(deltext+" mpin256.*")
os.system(deltext+" bls256.*")

os.system(deltext+" blsrev*.cpp")
#os.system(deltext+ " hpke*.* ")

# create library

if not nhs_selected :
    os.system(deltext+" newhope.cpp")
    os.system(deltext+" newhope.h")
#else :
#    os.system("mkdir examples")
#    os.system("mkdir examples"+slashtext+"testnhs")
#    os.system(copytext+" testnhs.ino "+"examples"+slashtext+"testnhs"+slashtext+"testnhs.ino")
os.system(deltext+" testnhs.ino")

#if curve_selected :
#    os.system("mkdir examples")
#    os.system("mkdir examples"+slashtext+"testecc")
#    os.system(copytext+" testecc.ino "+"examples"+slashtext+"testecc"+slashtext+"testecc.ino")
#    os.system("mkdir examples"+slashtext+"timeecc")
#    os.system(copytext+" timeecc.ino "+"examples"+slashtext+"timeecc"+slashtext+"timeecc.ino")
os.system(deltext+" testecc.ino")
os.system(deltext+" timeecc.ino")

#if not rsa_selected :
#    os.system(deltext+" X509.cpp")
#    os.system(deltext+" X509.h")
#else :
#    os.system("mkdir examples")
#    os.system("mkdir examples"+slashtext+"testrsa")
#    os.system(copytext+" testrsa.ino "+"examples"+slashtext+"testrsa"+slashtext+"testrsa.ino")
os.system(deltext+" testrsa.ino")


#if pfcurve_selected :
#    os.system("mkdir examples")
#    os.system("mkdir examples"+slashtext+"testbls")
#    os.system(copytext+" testbls.ino "+"examples"+slashtext+"testbls"+slashtext+"testbls.ino")
#    os.system("mkdir examples"+slashtext+"timepbc")
#    os.system(copytext+" timepbc.ino "+"examples"+slashtext+"timepbc"+slashtext+"timepbc.ino")
#    os.system(deltext+ " ecdh*.* ")
os.system(deltext+ " hpke*.* ")
os.system(deltext+" testbls.ino")
os.system(deltext+" timepbc.ino")

os.system(deltext+ " share*.* ")
os.system(deltext+ " x509.* ")

os.system("mkdir examples")
os.system("mkdir examples"+slashtext+"client")
os.system(copytext+" client.cpp "+"examples"+slashtext+"client"+slashtext+"client.ino")
os.system(deltext+" client.cpp")

# using miracl + ECC608a hardware
os.system(copytext+" tls_sal_mh.xpp "+"tls_sal.cpp")
os.system(deltext+" *.md")
os.system(deltext+" *.xpp")
os.system(deltext+" testx509.cpp")

if not selected(selection,1,ptr) and not selected(selection,2,ptr) and not selected(selection,19,ptr):
    os.system(deltext+" rom_field_F25519.cpp")
if not selected(selection,1,ptr) :
    os.system(deltext+" rom_curve_ED25519.cpp")
if not selected(selection,2,ptr) :
    os.system(deltext+" rom_curve_C25519.cpp")
if not selected(selection,3,ptr) :
    os.system(deltext+" rom_field_NIST256.cpp")
    os.system(deltext+" rom_curve_NIST256.cpp")
if not selected(selection,4,ptr) :
    os.system(deltext+" rom_field_BRAINPOOL.cpp")
    os.system(deltext+" rom_curve_BRAINPOOL.cpp")
if not selected(selection,5,ptr) :
    os.system(deltext+" rom_field_ANSSI.cpp")
    os.system(deltext+" rom_curve_ANSSI.cpp")
if not selected(selection,6,ptr) :
    os.system(deltext+" rom_field_HIFIVE.cpp")
    os.system(deltext+" rom_curve_HIFIVE.cpp")

if not selected(selection,7,ptr) and not selected(selection,21,ptr):
    os.system(deltext+" rom_field_GOLDILOCKS.cpp")

if not selected(selection,7,ptr) :
    os.system(deltext+" rom_curve_GOLDILOCKS.cpp")
if not selected(selection,8,ptr) :
    os.system(deltext+" rom_field_NIST384.cpp")
    os.system(deltext+" rom_curve_NIST384.cpp")
if not selected(selection,9,ptr) :
    os.system(deltext+" rom_field_C41417.cpp")
    os.system(deltext+" rom_curve_C41417.cpp")
if not selected(selection,10,ptr) :
    os.system(deltext+" rom_field_NIST521.cpp")
    os.system(deltext+" rom_curve_NIST521.cpp")
if not selected(selection,11,ptr) :
    os.system(deltext+" rom_field_F256PMW.cpp")
    os.system(deltext+" rom_curve_NUMS256W.cpp")
if not selected(selection,12,ptr) :
    os.system(deltext+" rom_field_F256PME.cpp")
    os.system(deltext+" rom_curve_NUMS256E.cpp")

if not selected(selection,13,ptr) and not selected(selection,14,ptr) :
    os.system(deltext+" rom_field_F384PM.cpp")
if not selected(selection,13,ptr) :
    os.system(deltext+" rom_curve_NUMS384W.cpp")
if not selected(selection,14,ptr) :
    os.system(deltext+" rom_curve_NUMS384E.cpp")

if not selected(selection,15,ptr) and not selected(selection,16,ptr) :
    os.system(deltext+" rom_field_F512PM.cpp")
if not selected(selection,15,ptr) :
    os.system(deltext+" rom_curve_NUMS512W.cpp")
if not selected(selection,16,ptr) :
    os.system(deltext+" rom_curve_NUMS512E.cpp")

if not selected(selection,17,ptr) :
    os.system(deltext+" rom_field_SECP256K1.cpp")
    os.system(deltext+" rom_curve_SECP256K1.cpp")

if not selected(selection,18,ptr) :
    os.system(deltext+" rom_field_SM2.cpp")
    os.system(deltext+" rom_curve_SM2.cpp")


if not selected(selection,19,ptr) :
    os.system(deltext+" rom_curve_C13318.cpp")

if not selected(selection,20,ptr) :
    os.system(deltext+" rom_field_JUBJUB.cpp")
    os.system(deltext+" rom_curve_JUBJUB.cpp")

if not selected(selection,21,ptr) :
    os.system(deltext+" rom_curve_X448.cpp")
if not selected(selection,22,ptr) :
    os.system(deltext+" rom_field_SECP160R1.cpp")
    os.system(deltext+" rom_curve_SECP160R1.cpp")
if not selected(selection,23,ptr) :
    os.system(deltext+" rom_field_C1174.cpp")
    os.system(deltext+" rom_curve_C1174.cpp")
if not selected(selection,24,ptr) :
    os.system(deltext+" rom_field_C1665.cpp")
    os.system(deltext+" rom_curve_C1665.cpp")

if not selected(selection,25,ptr) :
    os.system(deltext+" rom_field_MDC.cpp")
    os.system(deltext+" rom_curve_MDC.cpp")
if not selected(selection,26,ptr) :
    os.system(deltext+" rom_field_TWEEDLEDUM.cpp")
    os.system(deltext+" rom_curve_TWEEDLEDUM.cpp")
if not selected(selection,27,ptr) :
    os.system(deltext+" rom_field_TWEEDLEDEE.cpp")
    os.system(deltext+" rom_curve_TWEEDLEDEE.cpp")

if not selected(selection,28,ptr) :
    os.system(deltext+" rom_field_BN254.cpp")
    os.system(deltext+" rom_curve_BN254.cpp")
if not selected(selection,29,ptr) :
    os.system(deltext+" rom_field_BN254CX.cpp")
    os.system(deltext+" rom_curve_BN254CX.cpp")
if not selected(selection,30,ptr) :
    os.system(deltext+" rom_field_BLS12383.cpp")
    os.system(deltext+" rom_curve_BLS12383.cpp")
if not selected(selection,31,ptr) :
    os.system(deltext+" rom_field_BLS12381.cpp")
    os.system(deltext+" rom_curve_BLS12381.cpp")
if not selected(selection,32,ptr) :
    os.system(deltext+" rom_field_FP256BN.cpp")
    os.system(deltext+" rom_curve_FP256BN.cpp")
if not selected(selection,33,ptr) :
    os.system(deltext+" rom_field_FP512BN.cpp")
    os.system(deltext+" rom_curve_FP512BN.cpp")
if not selected(selection,34,ptr) :
    os.system(deltext+" rom_field_BLS12443.cpp")
    os.system(deltext+" rom_curve_BLS12443.cpp")

if not selected(selection,35,ptr) :
    os.system(deltext+" rom_field_BLS12461.cpp")
    os.system(deltext+" rom_curve_BLS12461.cpp")

if not selected(selection,36,ptr) :
    os.system(deltext+" rom_field_BN462.cpp")
    os.system(deltext+" rom_curve_BN462.cpp")

if not selected(selection,37,ptr) :
    os.system(deltext+" rom_field_BLS24479.cpp")
    os.system(deltext+" rom_curve_BLS24479.cpp")
if not selected(selection,38,ptr) :
    os.system(deltext+" rom_field_BLS48556.cpp")
    os.system(deltext+" rom_curve_BLS48556.cpp")

if not selected(selection,39,ptr) :
    os.system(deltext+" rom_field_BLS48581.cpp")
    os.system(deltext+" rom_curve_BLS48581.cpp")

if not selected(selection,40,ptr) :
    os.system(deltext+" rom_field_BLS48286.cpp")
    os.system(deltext+" rom_curve_BLS48286.cpp")

    os.system(deltext+" testbls.cpp")
    os.system(deltext+" testecc.cpp")
    os.system(deltext+" testmpin.cpp")
    os.system(deltext+" testhpke.cpp")
    os.system(deltext+" testhtp.cpp")
    os.system(deltext+" testnhs.cpp")

    os.system(deltext+" config*.py")
    os.system(deltext+" benchtest_all.cpp")
