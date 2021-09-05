#!/bin/bash
mkdir .temp
cd .temp
git clone https://github.com/miracl/core.git
cd core/c
python3 ./config
python3 ./config64.py --options=2 --options=3 --options=8 --options=41 --options=43
cd ../../../
cp .temp/core/c/core.a vendor/miracl/
cp .temp/core/c/core.h vendor/miracl/includes
cp .temp/core/c/arch.h vendor/miracl/includes
cp .temp/core/c/ecdh_*.h vendor/miracl/includes
cp .temp/core/c/ecp_*.h vendor/miracl/includes
cp .temp/core/c/fp_*.h vendor/miracl/includes
cp .temp/core/c/big_*.h vendor/miracl/includes
cp .temp/core/c/config_*.h vendor/miracl/includes
cp .temp/core/c/rsa*.h vendor/miracl/includes
cp tls_sal_m.xpp tls_sal.cpp
rm -rf .temp
