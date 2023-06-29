#ifndef TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
#define TFPF_HASH_DRBG_INCLUDE_HDRBG_H_ "1.0.0"

#ifdef __cplusplus
#include <cinttypes>
#include <cstddef>
#define uint8_t std::uint8_t
#define uint64_t std::uint64_t
#define size_t std::size_t
#else
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#endif

struct hdrbg_t;

#ifdef __cplusplus
extern "C"
{
#endif
struct hdrbg_t *hdrbg_new(bool dma);
void hdrbg_renew(struct hdrbg_t *hd);
bool hdrbg_gen(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, size_t r_length);
uint64_t hdrbg_rand(struct hdrbg_t *hd);
void hdrbg_delete(struct hdrbg_t *hd);
void hdrbg_test(void);
#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#undef uint8_t
#undef uint64_t
#undef size_t
#endif

#endif  // TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
