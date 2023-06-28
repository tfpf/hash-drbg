#ifndef TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
#define TFPF_HASH_DRBG_INCLUDE_HDRBG_H_

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

struct hdrbg_t;

#ifdef __cplusplus
extern "C"
{
#endif
struct hdrbg_t *hdrbg_new(void);
void hdrbg_renew(struct hdrbg_t *hd);
bool hdrbg_gen(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, size_t r_length);
void hdrbg_delete(struct hdrbg_t *hd);
void hdrbg_test(void);
#ifdef __cplusplus
}
#endif

#endif  // TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
