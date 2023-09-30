#! /usr/bin/env sh

set -e

os=$(uname 2>/dev/null)
case $os in
    (Darwin | Linux);;
    (CYGWIN* | MINGW* | MSYS*) alias sudo='';;
    (*)
        printf "Unknown OS: '$os'. Edit 'run.sh' as necessary and retry.\n" >&2
        exit 1
    ;;
esac

uninstall()
{
    im=build/install_manifest.txt
    if [ ! -f $im ]
    then
        printf "Cannot find install manifest.\n" >&2
        exit 1
    fi
    sudo rm -v $(cat $im)
}

install()
{
    mkdir -p build
    cd build
    cmake ..
    cmake --build . --parallel
    sudo cmake --install . --config Release
}

if [ "$1" = rm ]
then
    uninstall
    exit
fi

if [ "$0" = sh ]
then
    target=/tmp/hash-drbg-$(date +%s)
    git clone https://github.com/tfpf/hash-drbg.git $target
    cd $target
fi
install
