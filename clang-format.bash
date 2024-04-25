#! /usr/bin/env bash

shopt -s extglob globstar

# Switch to the directory containing the script so that relative paths may be
# used.
cd "${0%/*}"
files=(!(build)/**/*.c **/*.cc **/*.h)
if [ "$1" = check ]
then
    clang-format --verbose --dry-run -Werror ${files[@]}
else
    clang-format --verbose -i ${files[@]}
fi
