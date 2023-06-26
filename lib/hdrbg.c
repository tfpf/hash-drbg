#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

// All numbers are in bytes.
#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_SEED_LENGTH 55
#define HDRBG_OUTPUT_LENGTH 32

struct hdrbg_t
{
    uint8_t V[HDRBG_SEED_LENGTH + 1];
    uint8_t C[HDRBG_SEED_LENGTH + 1];
    uint64_t gen_count;
    uint64_t seed_count;
};

/******************************************************************************
 * Create and/or initialise an HDRBG object with 256-bit security strength.
 * Prediction resistance is not supported. No personalisation string is used.
 *
 * @param hd HDRBG object to initialise. If `NULL`, a new HDRBG object will be
 *     created and initialised.
 *
 * @return Initialised HDRBG object.
 *****************************************************************************/
struct hdrbg_t *
hdrbg_init(struct hdrbg_t *hd)
{
    // Create if necessary.
    if(hd == NULL)
    {
        hd = malloc(sizeof *hd);
        hd->gen_count = 0;
        hd->seed_count = 0;
    }
    ++hd->seed_count;

    // Obtain some entropy and a nonce. Construct the nonce using the timestamp
    // and a sequence number.
    uint8_t seeder[HDRBG_SECURITY_STRENGTH + 4 + 8];
    uint8_t *s_iter = seeder;
    FILE *rd = fopen("/dev/urandom", "rb");
    s_iter += fread(s_iter, sizeof *s_iter, HDRBG_SECURITY_STRENGTH, rd);
    fclose(rd);
    s_iter += memdecompose(s_iter, 4, (uint32_t)time(NULL));
    s_iter += memdecompose(s_iter, 8, hd->seed_count);

    // Obtain the seed and constant.
    hash_df(seeder, sizeof seeder / sizeof *seeder, hd->V + 1, HDRBG_SEED_LENGTH);
    hd->V[0] = 0x00U;
    hash_df(hd->V, HDRBG_SEED_LENGTH + 1, hd->C + 1, HDRBG_SEED_LENGTH);
memdump(hd->V, HDRBG_SEED_LENGTH + 1);
memdump(hd->C, HDRBG_SEED_LENGTH + 1);
    return hd;
}

/******************************************************************************
 * Use a hash function to transform the input bytes into the required number of
 * output bytes.
 *
 * @param m_bytes_ Input bytes.
 * @param m_length_ Number of input bytes.
 * @param h_bytes Array to store the output bytes in. (It must have enough
 *     space to store the required number of output bytes.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
void
hash_df(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes, size_t h_length)
{
memdump(m_bytes_, m_length_);
    // Construct (a part of) the data to be hashed.
    size_t m_length = 5 + m_length_;
    uint8_t *m_bytes = malloc(m_length * sizeof *m_bytes);
    uint32_t bits = (uint32_t)h_length << 3;
    memdecompose(m_bytes + 1, 4, bits);
    memcpy(m_bytes + 5, m_bytes_, m_length_ * sizeof *m_bytes_);

    // Hash repeatedly.
    size_t iterations = (h_length - 1) / HDRBG_OUTPUT_LENGTH + 1;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    for(size_t i = 1; i <= iterations; ++i)
    {
        m_bytes[0] = i;
memdump(m_bytes, m_length);
        sha256(m_bytes, m_length, tmp);
        size_t length = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, length * sizeof *h_bytes);
        h_length -= length;
        h_bytes += length;
    }
}
