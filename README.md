* Elaine Barker and John Kelsey (2015) "Recommendation for Random Number Generation Using Deterministic Random Bit
  Generators". NIST SP 800-90A Rev. 1, doi:10.6028/NIST.SP.800-90Ar1.
* Elaine Barker (2020) "Recommendation for Key Management: Part 1 – General". NIST SP 800-57 Part 1 Rev. 5,
  doi:10.6028/NIST.SP.800-57pt1r5.
* National Institute of Standards and Technology (2015) "Secure Hash Standard". FIPS PUB 180-4,
  doi:10.6028/NIST.FIPS.180-4.

# Hash Deterministic Random Bit Generator (HDRBG): Cryptographically Secure Pseudorandom Number Generator
This package provides a cryptographically secure pseudorandom number generator for C, C++ and Python. It is mostly
compliant with the specification given in NIST SP 800-90A.

See [`doc`](doc) for the documentation of this package. [`examples`](examples) contains usage examples. For performance
analysis, go to [`benchmarks`](benchmarks).

## Installation Requirements
These are the versions I have tested the installation with. Older versions may also work. You may not need all of
these, depending on how and what you are installing
* CMake ≥ 3.22
* cURL ≥ 7.68.0
* GCC ≥ 9.4.0 or Clang ≥ 12.0.0
* Git ≥ 2.30.2
* GNU Make ≥ 4.2.1
* CPython ≥ 3.8 and its C headers and library
* pip ≥ 23.0

On Windows, these are available natively via [MSYS2](https://www.msys2.org) and in a Linux environment via
[WSL](https://learn.microsoft.com/en-us/windows/wsl/about). On macOS, they can be installed using
[Homebrew](https://brew.sh/); however, their Apple-specific variants provided by
[Xcode](https://apps.apple.com/app/xcode/id497799835) should also be fine. I am fairly sure that this will work on
macOS, though I don't have a Mac to test it. (I'm trying to figure out how to use a macOS runner on GitHub Actions.)

The installation commands mentioned below must be entered in
* the terminal if you are on Linux/macOS, or
* the MSYS2 terminal or WSL terminal if you are on Windows.

## Install for C (and C++)
```shell
curl https://raw.githubusercontent.com/tfpf/hash-drbg/main/run.sh | sh
```
or
```shell
git clone https://github.com/tfpf/hash-drbg.git
cd hash-drbg
./run.sh
```

### Quick Start
Put the following code in a file `example.c`:
```C
#include <hdrbg.h>
#include <stdio.h>

int main(void)
{
    hdrbg_init(0);
    for(int i = 0; i < 10; ++i)
    {
        long long unsigned r = hdrbg_rand(NULL);
        printf("%llu\n", r);
    }
}
```
compile it with
```
gcc -o example example.c -lhdrbg
```
and run it using
```sh
./example
```
to see some random numbers.

## Install for Python
```shell
pip install git+https://github.com/tfpf/hash-drbg.git
```
or
```shell
git clone https://github.com/tfpf/hash-drbg.git
cd hash-drbg
pip install .
```

This does not currently work on MSYS2.
