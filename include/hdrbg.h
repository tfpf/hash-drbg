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
enum hdrbg_err_t
{
    HDRBG_ERR_NONE,
    HDRBG_ERR_OUT_OF_MEMORY,
};

#ifdef __cplusplus
extern "C"
{
#endif
enum hdrbg_err_t hdrbg_err_get(void);
struct hdrbg_t *hdrbg_init(bool dma);
void hdrbg_reinit(struct hdrbg_t *hd);
bool hdrbg_fill(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, size_t r_length);
uint64_t hdrbg_rand(struct hdrbg_t *hd);
uint64_t hdrbg_uint(struct hdrbg_t *hd, uint64_t modulus);
int64_t hdrbg_span(struct hdrbg_t *hd, int64_t left, int64_t right);
double long hdrbg_real(struct hdrbg_t *hd);
void hdrbg_zero(struct hdrbg_t *hd);
void hdrbg_dump(uint8_t const *m_bytes, size_t m_length);
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
