#ifndef TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_
#define TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_

#include <inttypes.h>
#include <stddef.h>

void memclear(void *ptr, size_t sz);
uint64_t memcompose(uint8_t const *m_bytes, size_t m_length);
size_t memdecompose(uint8_t *m_bytes, size_t m_length, uint64_t value);

#endif  // TFPF_HASH_DRBG_INCLUDE_EXTRAS_H_
