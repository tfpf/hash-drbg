#! /usr/bin/env sh

if [ "$1" = rm ]
then
    im=build/install_manifest.txt
    if [ ! -f $im ]
    then
        printf "Cannot find install manifest!\n" >&2
        exit 1
    fi
    while read fname
    do
        sudo rm -v $fname
    done < $im
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
sudo make --jobs=4 install
case $(uname 2>/dev/null) in
    (Linux) sudo ldconfig;;
esac
