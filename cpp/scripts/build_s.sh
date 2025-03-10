#!/bin/bash

# Make sure script is run from main repo location
if [ ! -f CMakeLists.txt ] ; then
    echo "Please run this script from the main repo like:"
    echo "\tsh scripts/build.sh"
    exit
fi

# Create temp folder to pull and build Miracl library
mkdir .temp
mkdir -p sal/miracl/includes
cd .temp
git clone https://github.com/miracl/core.git
cd core/cpp
python3 ./config64.py --options=2 --options=3 --option=7 --options=8 --options=31 --options=42 --options=44
cd ../../../

# Copy built library and includes to SAL
cp .temp/core/cpp/core.a sal/miracl
cp .temp/core/cpp/*.h sal/miracl/includes

# Remove temp folder
rm -rf .temp

# Create temporary build folder
mkdir .build
cd .build

# Build library and client application
cmake -DSAL=MIRACL_SODIUM ..
make

# Create build folder and copy built artefacts
mkdir -p ../build
cp client ../build
cp libtiitls.a ../build
cd ../

cp sal/miracl/core.a build/.
cp include/tls_*.h build/.
cp include/tls1_3.h build/.
cp lib/tls*.cpp build/.
cp sal/miracl/includes/core.h build/.
cp sal/miracl/includes/arch.h build/.
cp src/desktop/client.cpp build/.

# Clean repo
rm -rf .build
rm -rf sal/miracl