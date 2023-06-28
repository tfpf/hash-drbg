#! /usr/bin/env sh

if [ "$0" = sh ]
then
    target=/tmp/hash-drbg-$(date +%s)
    git clone https://github.com/tfpf/hash-drbg.git $target
    cd $target
fi
case $(uname 2>/dev/null) in
    MINGW* | MSYS*) make --jobs=4 "$@" install;;
    Linux) sudo make --jobs=4 "$@" install;;
esac
