* Elaine Barker and John Kelsey (2015) Recommendation for Random Number Generation Using Deterministic Random Bit
  Generators. (National Institute of Standards and Technology, Gaithersburg, MD, USA), NIST SP 800-90A, Rev. 1.
* Elaine Barker (2020) Recommendation for Key Management: Part 1 – General. (National Institute of Standards and
  Technology, Gaithersburg, MD, USA), NIST SP 800-57 Part 1, Rev. 5.
* National Institute of Standards and Technology (2015) Secure Hash Standard. (National Institute of Standards and
  Technology, Gaithersburg, MD, USA), FIPS PUB 180-4.

# Hash DRBG (HDRBG): Cryptographically Secure Pseudorandom Number Generator
This package provides a cryptographically secure pseudorandom number generator for C and C++. It is mostly compliant
with the specification given in NIST SP 800-90A.

See [`doc`](doc) for the documentation of this package. [`examples`](examples) contains usage examples.

## Installation Requirements
These are the versions I have tested the installation with. Older versions may also work.
* cURL ≥ 7.68.0
* GCC ≥ 9.4.0 or Clang ≥ 12.0.0
* Git ≥ 2.30.2
* GNU Make ≥ 4.2.1

On Windows, these are available via [MSYS2](https://www.msys2.org).

The installation commands mentioned below must be entered in the terminal if you are on Linux or the MSYS2 terminal if
you are on Windows.

## Install for C (and C++)
```
curl https://raw.githubusercontent.com/tfpf/hash-drbg/main/install.sh | sh
```
or
```
git clone https://github.com/tfpf/hash-drbg.git
cd hash-drbg
./install.sh
```

### Quick Start
Put the following code in a file `example.c`:
```C
#include <hdrbg.h>
#include <stdio.h>

int main(void)
{
    hdrbg_new(0);
    for(int i = 0; i < 10; ++i)
    {
        printf("%llu\n", hdrbg_rand(NULL));
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
