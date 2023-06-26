#ifndef TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
#define TFPF_HASH_DRBG_INCLUDE_HDRBG_H_

struct hdrbg_t;
struct hdrbg_t *hdrbg_init(struct hdrbg_t *hd);
void hash_df(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes, size_t h_length);

#endif  // TFPF_HASH_DRBG_INCLUDE_HDRBG_H_
