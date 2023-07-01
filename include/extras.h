#ifndef TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_
#define TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_

#include <inttypes.h>
#include <stddef.h>

void memclear(void *ptr, size_t size);
uint64_t memcompose(uint8_t const *addr, size_t length);
size_t memdecompose(uint8_t *addr, size_t length, uint64_t value);

#endif  // TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_
