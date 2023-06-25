#ifndef TFPF_HASH_DRBG_INCLUDE_MISC_H_
#define TFPF_HASH_DRBG_INCLUDE_MISC_H_

#include <inttypes.h>
#include <stddef.h>

void memdump(uint8_t const *bytes, size_t length);
void memclear(void *ptr, size_t size);

#endif  // TFPF_HASH_DRBG_INCLUDE_MISC_H_
