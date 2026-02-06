#!/bin/bash

# Make sure script is run from main repo location
if [ ! -f CMakeLists.txt ] ; then
    echo "Please run this script from the main repo like:"
    echo "\tsh scripts/build.sh"
    exit
fi

args=$@

chkarg() {
    for arg in $args
    do
        if [ $1 -eq $arg ];
        then
            return "0"
        fi
    done
    return "1"
}

if chkarg "-1"
then
    echo "Building using Miracl"
    sh ./scripts/build_m.sh
elif chkarg "-2"
then
    echo "Building using LibSodium + Miracl"
    sh ./scripts/build_s.sh
elif chkarg "-3"
then
    echo "Building using TLSECC + Miracl"
    sh ./scripts/build_t.sh
elif chkarg "-4"
then
    echo "Building using Miracl + SQISIGN"
    sh ./scripts/build_q.sh
else
    echo "No arguments specified\n"
    echo "Parameters:"
    echo " -1\tMiracl"
    echo " -2\tMiracl + LibSodium"   
    echo " -3\tMiracl + TLSECC"   
    echo " -4\tMiracl + SQISIGN"   
    echo " -5\tCustom Library" 
    exit
fi