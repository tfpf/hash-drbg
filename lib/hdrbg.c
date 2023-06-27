#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef __STDC_NO_ATOMICS__
#include <stdatomic.h>
#endif

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_SEED_LENGTH 55
#define HDRBG_OUTPUT_LENGTH 32
#define HDRBG_RESEED_INTERVAL ((uint64_t)1 << 48)

#ifndef __STDC_NO_ATOMICS__
static _Atomic uint64_t
#else
static uint64_t
#endif
seq_num = 0;

struct hdrbg_t
{
    // The first member is prepended with a byte of zeros whenever it is
    // processed, so keep an extra byte.
    uint8_t V[HDRBG_SEED_LENGTH + 1];
    uint8_t C[HDRBG_SEED_LENGTH];
    uint64_t gen_count;
};

/******************************************************************************
 * Hash derivation function. Transform the input bytes into the required number
 * of output bytes using a hash function.
 *
 * @param m_bytes_ Input bytes.
 * @param m_length_ Number of input bytes.
 * @param h_bytes Array to store the output bytes in. (It must have enough
 *     space to store the required number of output bytes.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
static void
hash_df(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes, size_t h_length)
{
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
        sha256(m_bytes, m_length, tmp);
        size_t length = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, length * sizeof *h_bytes);
        h_length -= length;
        h_bytes += length;
    }
    memclear(m_bytes, m_length * sizeof *m_bytes);
    free(m_bytes);
}

/******************************************************************************
 * Set the members of an HDRBG object.
 *
 * @param hd HDRBG object.
 * @param seeder Array to derive the values of the members from.
 * @param length Number of elements in the array.
 *****************************************************************************/
static void
hdrbg_seed(struct hdrbg_t *hd, uint8_t *seeder, size_t length)
{
    hd->V[0] = 0x00U;
    hash_df(seeder, length, hd->V + 1, HDRBG_SEED_LENGTH);
    hash_df(hd->V, HDRBG_SEED_LENGTH + 1, hd->C, HDRBG_SEED_LENGTH);
    hd->gen_count = 0;
}

/******************************************************************************
 * Create and initialise an HDRBG object with 256-bit security strength.
 * Prediction resistance is supported. No personalisation string is used.
 *
 * @return Initialised HDRBG object.
 *****************************************************************************/
struct hdrbg_t *
hdrbg_new(void)
{
    struct hdrbg_t *hd = malloc(sizeof *hd);

    // Obtain some entropy and a nonce. Construct the nonce using the timestamp
    // and a sequence number.
    uint8_t seeder[HDRBG_SECURITY_STRENGTH + 12];
    uint8_t *s_iter = seeder;
    FILE *rd = fopen("/dev/urandom", "rb");
    s_iter += fread(s_iter, sizeof *s_iter, HDRBG_SECURITY_STRENGTH, rd);
    fclose(rd);
    s_iter += memdecompose(s_iter, 4, (uint32_t)time(NULL));
    s_iter += memdecompose(s_iter, 8, ++seq_num);

    hdrbg_seed(hd, seeder, sizeof seeder / sizeof *seeder);
    return hd;
}

/******************************************************************************
 * Reinitialise an HDRBG object previously created using `hdrbg_new` with
 * prediction resistance. No additional input is used.
 *
 * @param hd HDRBG object.
 *****************************************************************************/
void
hdrbg_renew(struct hdrbg_t *hd)
{
    // Obtain some entropy.
    uint8_t seeder[1 + HDRBG_SEED_LENGTH + HDRBG_SECURITY_STRENGTH];
    seeder[0] = 0x01U;
    memcpy(seeder + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *seeder);
    FILE *rd = fopen("/dev/urandom", "rb");
    fread(seeder + 1 + HDRBG_SEED_LENGTH, sizeof *seeder, HDRBG_SECURITY_STRENGTH, rd);
    fclose(rd);

    hdrbg_seed(hd, seeder, sizeof seeder / sizeof *seeder);
}

/******************************************************************************
 * Clear and destroy an HDRBG object previously created using `hdrbg_new`.
 *
 * @param hd HDRBG object.
 *****************************************************************************/
void
hdrbg_delete(struct hdrbg_t *hd)
{
    memclear(hd, sizeof *hd);
    free(hd);
}
