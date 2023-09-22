#! /usr/bin/env sh

if [ "$0" = sh ]
then
    target=/tmp/hash-drbg-$(date +%s)
    git clone https://github.com/tfpf/hash-drbg.git $target
    cd $target
fi
os=$(uname 2>/dev/null)
printf "Detected: '$os'\n"
case $os in
    (MINGW* | MSYS*) make --jobs=4 "$@" install;;
    (Linux | Darwin) sudo make --jobs=4 "$@" install;;
esac
