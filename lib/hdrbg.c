#include <inttypes.h>
#include <stdbool.h>
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
#define HDRBG_REQUEST_LIMIT  (1ULL << 16)
#define HDRBG_RESEED_INTERVAL (1ULL << 48)

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
 * Add two numbers.
 *
 * @param a Array of bytes of the first number in big-endian order. The sum
 *     will by placed in this array, discarding the carried byte (if any).
 * @param a_length Number of bytes of the first number.
 * @param b Array of bytes of the second number in big-endian order.
 * @param b_length Number of bytes of the second number. Must be less than or
 *     equal to the number of bytes of the first number.
 *****************************************************************************/
static void
add_bignums(uint8_t *a, size_t a_length, uint8_t *b, size_t b_length)
{
    int unsigned carry = 0;
    size_t ai = a_length, bi = b_length;
    for(; ai > 0 && bi > 0; --ai, --bi)
    {
        carry = a[ai - 1] + carry + b[bi - 1];
        a[ai - 1] = carry;
        carry >>= 8;
    }
    for(; ai > 0; --ai)
    {
        carry += a[ai - 1];
        a[ai - 1] = carry;
        carry >>= 8;
    }
}


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
    // Construct the data to be hashed.
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
 * Hash generator. Transform the input bytes into the required number of output
 * bytes using a hash function.
 *
 * @param m_bytes_ Input bytes. Must be an array of length `HDRBG_SEED_LENGTH`.
 * @param h_bytes Array to store the output bytes in. (It must have enough
 *     space to store the required number of output bytes.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
static void
hash_gen(uint8_t const *m_bytes_, uint8_t *h_bytes, size_t h_length)
{
    // Construct the data to be hashed.
    uint8_t m_bytes[HDRBG_SEED_LENGTH];
    memcpy(m_bytes, m_bytes_, sizeof m_bytes);

    // Hash repeatedly.
    size_t iterations = (h_length - 1) / HDRBG_OUTPUT_LENGTH + 1;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    for(size_t i = 0; i < iterations; ++i)
    {
        sha256(m_bytes, HDRBG_SEED_LENGTH, tmp);
        size_t length = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, length * sizeof *h_bytes);
        h_length -= length;
        h_bytes += length;
        uint8_t b = 1;
        add_bignums(m_bytes, HDRBG_SEED_LENGTH, &b, 1);
    }
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
 * Prediction resistance is supported. A personalisation string is not used.
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
 * Reinitialise an HDRBG object. Additional input is not used.
 *
 * @param hd HDRBG object. Must have been created using `hdrbg_new`.
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
 * Generate cryptographically secure pseudorandom bytes. Additional input is
 * not used.
 *
 * @param hd HDRBG object. Must have been created using `hdrbg_new`.
 * @param prediction_resistance If `true`, the HDRBG object will be
 *     reinitialised before generating the bytes. If `false`, the bytes will be
 *     generated directly.
 * @param r_bytes Array to store the output bytes in. (It must have enough
 *     space to store the required number of output bytes.)
 * @param r_length Number of output bytes required. At most 65536.
 *
 * @return `true` if the bytes were generated, else `false`.
 *****************************************************************************/
bool
hdrbg_gen(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, size_t r_length)
{
    if(r_length > HDRBG_REQUEST_LIMIT)
    {
        return false;
    }
    if(prediction_resistance || hd->gen_count > HDRBG_RESEED_INTERVAL)
    {
        hdrbg_renew(hd);
    }
    hash_gen(hd->V + 1, r_bytes, r_length);

    // Mutate the state.
    hd->V[0] = 0x03U;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    sha256(hd->V, HDRBG_SEED_LENGTH + 1, tmp);
    uint8_t gen_count[8];
    memdecompose(gen_count, 8, hd->gen_count);
    add_bignums(hd->V + 1, HDRBG_SEED_LENGTH, tmp, HDRBG_OUTPUT_LENGTH);
    add_bignums(hd->V + 1, HDRBG_SEED_LENGTH, hd->C, HDRBG_SEED_LENGTH);
    add_bignums(hd->V + 1, HDRBG_SEED_LENGTH, gen_count, 8);
    ++hd->gen_count;
    return true;
}

/******************************************************************************
 * Clear and destroy an HDRBG object.
 *
 * @param hd HDRBG object. Must have been created using `hdrbg_new`.
 *****************************************************************************/
void
hdrbg_delete(struct hdrbg_t *hd)
{
    memclear(hd, sizeof *hd);
    free(hd);
}
