#ifndef TFPF_HASH_DRBG_INCLUDE_SHA_H_
#define TFPF_HASH_DRBG_INCLUDE_SHA_H_

#include <inttypes.h>
#include <stddef.h>

uint8_t *sha256(uint8_t const *message_, size_t length_, uint8_t *h_bytes);

#endif  // TFPF_HASH_DRBG_INCLUDE_SHA_H_
