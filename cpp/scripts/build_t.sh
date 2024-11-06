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
python3 ./config64.py --options=31 --options=42 --options=44
cd ../../../

# Copy built library and includes to SAL
cp .temp/core/cpp/core.a sal/miracl
cp .temp/core/cpp/*.h sal/miracl/includes

# Remove temp folder
rm -rf .temp



# Create temp folder to pull and build TLSECC library
mkdir .temp
cd .temp
git clone https://github.com/mcarrickscott/TLSECC
cd TLSECC
cp c64/* .
cp include64/* .
gcc -O2 -c *.c
ar rc tlsecc.a *.o

cd ../../

cp .temp/TLSECC/tlsecc.a sal/miracl
cp .temp/TLSECC/tlsecc.h sal/miracl/includes


# Remove temp folder
rm -rf .temp




# Create temporary build folder
mkdir .build
cd .build

# Build library and client application
cmake -DSAL=MIRACL_TLSECC ..
make

# Create build folder and copy built artefacts
mkdir -p ../build
cp client ../build
cp libtiitls.a ../build
cd ../

# Clean repo
rm -rf .build
rm -rf sal/miracl