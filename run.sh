#! /usr/bin/env sh

if [ "$1" = rm ]
then
    im=build/install_manifest.txt
    if [ ! -f $im ]
    then
        printf "Cannot find install manifest!\n" >&2
        exit 1
    fi
    sudo rm -v $(cat build/install_manifest.txt)
    exit
fi

if [ "$0" = sh ]
then
    target=/tmp/hash-drbg-$(date +%s)
    git clone https://github.com/tfpf/hash-drbg.git $target
    cd $target
fi
mkdir -p build && cd build
cmake ..
sudo make -j install
case $(uname 2>/dev/null) in
    (Linux) sudo ldconfig;;
esac
