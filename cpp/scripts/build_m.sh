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
python3 ./config64.py --options=2 --options=3 --options=8 --options=41 --options=43
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
cmake -DSAL=MIRACL ..
make

# Create build folder and copy built artefacts
mkdir -p ../build
cp client ../build
cp libtiitls.a ../build
cd ../

# Clean repo
rm -rf .build
rm -rf sal/miracl