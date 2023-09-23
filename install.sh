#! /usr/bin/env sh

if [ "$0" = sh ]
then
    target=/tmp/hash-drbg-$(date +%s)
    git clone https://github.com/tfpf/hash-drbg.git $target
    cd $target
fi
mkdir -p build && cd build
cmake ..
sudo make --jobs=4 install
