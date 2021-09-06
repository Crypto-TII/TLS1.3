#!/bin/bash
mkdir .temp
cd .temp
git clone https://github.com/miracl/core.git
cd core/cpp
python3 ./config64.py --options=2 --options=3 --options=8 --options=41 --options=43
cd ../../../
cp .temp/core/cpp/core.a vendor/miracl/
cp .temp/core/cpp/*.h vendor/miracl/includes
cp tls_sal_m.xpp tls_sal.cpp
rm -rf .temp
