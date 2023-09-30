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
* CPython ≥ 3.8 and its C headers and library
* cURL ≥ 7.68.0
* GCC ≥ 9.4.0 or Clang ≥ 12.0.0
* Git ≥ 2.30.2
* GNU Make ≥ 4.2.1
* pip ≥ 23.0
* pkg-config ≥ 0.29.2 or pkgconf ≥ 1.8.0

On Windows, these are available natively via [MSYS2](https://www.msys2.org) (not recommended) and
[Cygwin](https://www.cygwin.com), and in a Linux environment via
[WSL](https://learn.microsoft.com/en-us/windows/wsl/about). On macOS, they can be installed using
[Homebrew](https://brew.sh); however, their Apple-specific variants provided by
[Xcode](https://apps.apple.com/app/xcode/id497799835) should also be fine.

## Troubleshooting Information
Installing directly on Windows is a massive headache. MSVC adds some unnecessary flags which are incompatible with
optimisation flags, so the program does not compile. Its concurrency library doesn't properly implement atomic data
types, and isn't standard-compliant. Further, Windows does not provide a random device. That is why I suggest MSYS2 and
Cygwin. If installation fails for you, check the [workflows](.github/workflows) to see how I got it working.

![unix](https://github.com/tfpf/hash-drbg/actions/workflows/unix.yml/badge.svg)
![cygwin](https://github.com/tfpf/hash-drbg/actions/workflows/cygwin.yml/badge.svg)

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

Next, set `LD_LIBRARY_PATH` and `PKG_CONFIG_PATH`.
```shell
export LD_LIBRARY_PATH=/usr/local/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
export PKG_CONFIG_PATH=/usr/local/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
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
gcc example.c -o example $(pkg-config --cflags --libs hdrbg)
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
