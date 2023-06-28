#include <assert.h>
#include <ctype.h>
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

// Characteristics of test vectors.
#define HDRBG_TV_SEEDER_LENGTH 48
#define HDRBG_TV_RESEEDER_LENGTH (HDRBG_SEED_LENGTH + 33)
#define HDRBG_TV_REQUEST_LENGTH 128

#ifndef __STDC_NO_ATOMICS__
static _Atomic uint64_t
#else
static uint64_t
#endif
seq_num = 0;

// To suppress warnings about unused return values when I know what I am doing.
static int _;

struct hdrbg_t
{
    // The first member is prepended with a byte whenever it is processed, so
    // keep an extra byte.
    uint8_t V[HDRBG_SEED_LENGTH + 1];
    uint8_t C[HDRBG_SEED_LENGTH];
    uint64_t gen_count;
};

/******************************************************************************
 * Add two numbers. Overwrite the first number with the result, disregarding
 * any carried bytes.
 *
 * @param a_bytes Array of bytes of the first number in big-endian order.
 * @param a_length Number of bytes of the first number.
 * @param b_bytes Array of bytes of the second number in big-endian order.
 * @param b_length Number of bytes of the second number. Must be less than or
 *     equal to the number of bytes of the first number.
 *****************************************************************************/
static void
add_accumulate(uint8_t *a_bytes, size_t a_length, uint8_t const *b_bytes, size_t b_length)
{
    int unsigned carry = 0;
    size_t ai = a_length, bi = b_length;
    for(; ai > 0 && bi > 0; --ai, --bi)
    {
        carry = a_bytes[ai - 1] + carry + b_bytes[bi - 1];
        a_bytes[ai - 1] = carry;
        carry >>= 8;
    }
    for(; ai > 0; --ai)
    {
        carry += a_bytes[ai - 1];
        a_bytes[ai - 1] = carry;
        carry >>= 8;
    }
}

/******************************************************************************
 * Hash derivation function. Transform the input bytes into the required number
 * of output bytes using a hash function.
 *
 * @param m_bytes_ Input bytes.
 * @param m_length_ Number of input bytes.
 * @param h_bytes Array to store the output bytes in. (It must have sufficient
 *     space for `h_length` elements.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
static void
hash_df(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes, size_t h_length)
{
    // Construct the data to be hashed.
    size_t m_length = 5 + m_length_;
    uint8_t *m_bytes = malloc(m_length * sizeof *m_bytes);
    uint32_t nbits = (uint32_t)h_length << 3;
    memdecompose(m_bytes + 1, 4, nbits);
    memcpy(m_bytes + 5, m_bytes_, m_length_ * sizeof *m_bytes_);

    // Hash repeatedly.
    size_t iterations = (h_length - 1) / HDRBG_OUTPUT_LENGTH + 1;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    for(size_t i = 1; i <= iterations; ++i)
    {
        m_bytes[0] = i;
        sha256(m_bytes, m_length, tmp);
        size_t len = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, len * sizeof *h_bytes);
        h_length -= len;
        h_bytes += len;
    }
    memclear(m_bytes, m_length * sizeof *m_bytes);
    free(m_bytes);
}

/******************************************************************************
 * Hash generator. Transform the input bytes into the required number of output
 * bytes using a hash function.
 *
 * @param m_bytes_ Input bytes. Must be an array of length `HDRBG_SEED_LENGTH`.
 * @param h_bytes Array to store the output bytes in. (It must have sufficient
 *     space for `h_length` elements.)
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
    uint8_t one = 1;
    for(size_t i = 0; i < iterations; ++i)
    {
        sha256(m_bytes, HDRBG_SEED_LENGTH, tmp);
        size_t len = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, len * sizeof *h_bytes);
        h_length -= len;
        h_bytes += len;
        add_accumulate(m_bytes, HDRBG_SEED_LENGTH, &one, 1);
    }
}

/******************************************************************************
 * Set the members of an HDRBG object.
 *
 * @param hd HDRBG object.
 * @param s_bytes Array to derive the values of the members from.
 * @param s_length Number of elements in the array.
 *****************************************************************************/
static void
hdrbg_seed(struct hdrbg_t *hd, uint8_t *s_bytes, size_t s_length)
{
    hd->V[0] = 0x00U;
    hash_df(s_bytes, s_length, hd->V + 1, HDRBG_SEED_LENGTH);
    hash_df(hd->V, HDRBG_SEED_LENGTH + 1, hd->C, HDRBG_SEED_LENGTH);
    hd->gen_count = 1;
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
    uint8_t reseeder[1 + HDRBG_SEED_LENGTH + HDRBG_SECURITY_STRENGTH];
    uint8_t *r_iter = reseeder;
    *r_iter++ = 0x01U;
    memcpy(r_iter, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseeder);
    r_iter += HDRBG_SEED_LENGTH;
    FILE *rd = fopen("/dev/urandom", "rb");
    r_iter += fread(r_iter, sizeof *reseeder, HDRBG_SECURITY_STRENGTH, rd);
    fclose(rd);

    hdrbg_seed(hd, reseeder, sizeof reseeder / sizeof *reseeder);
}

/******************************************************************************
 * Generate cryptographically secure pseudorandom bytes. Additional input is
 * not used.
 *
 * @param hd HDRBG object. Must have been created using `hdrbg_new`.
 * @param prediction_resistance If `true`, the HDRBG object will be
 *     reinitialised before generating the bytes. If `false`, the bytes will be
 *     generated directly.
 * @param r_bytes Array to store the output bytes in. (It must have sufficient
 *     space for `r_length` elements.)
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
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, tmp, HDRBG_OUTPUT_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, hd->C, HDRBG_SEED_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, gen_count, 8);
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

/******************************************************************************
 * Read hexadecimal characters from a stream. Store the bytes of the number
 * they represent in a big-endian array.
 *
 * @param tv Stream to read from.
 * @param m_bytes Array to store the bytes in. (It must have sufficient space
 *     for `m_length` elements.)
 * @param m_length Number of bytes to store.
 *****************************************************************************/
static void
streamtobytes(FILE *tv, uint8_t *m_bytes, size_t m_length)
{
    while(m_length-- > 0)
    {
        char s[3];
        if(fscanf(tv, " %2s", s) != 1)
        {
            return;
        }
        *m_bytes++ = strtol(s, NULL, 16);
    }
}

/******************************************************************************
 * Verify that the cryptographically secure pseudorandom number generator is
 * working as specified. This function is meant for testing purposes only;
 * using it outside the test environment may result in undefined behaviour.
 *****************************************************************************/
void
hdrbg_test(void)
{
    struct hdrbg_t *hd = malloc(sizeof *hd);
    FILE *tv = fopen("Hash_DRBG.txt", "r");

    size_t count;
    uint8_t seeder[HDRBG_TV_SEEDER_LENGTH];
    uint8_t reseeder[HDRBG_TV_RESEEDER_LENGTH] = {0x01U};
    uint8_t expected[HDRBG_TV_REQUEST_LENGTH];
    uint8_t observed[HDRBG_TV_REQUEST_LENGTH];

    // Without prediction resistance.
    _ = fscanf(tv, "%zu", &count);
    for(size_t i = 0; i < count; ++i)
    {
        printf("Running test %zu/%zu without prediction resistance.\r", i + 1, count);
        streamtobytes(tv, seeder, HDRBG_TV_SEEDER_LENGTH);
        hdrbg_seed(hd, seeder, HDRBG_TV_SEEDER_LENGTH);
        memcpy(reseeder + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseeder);
        streamtobytes(tv, reseeder + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_RESEEDER_LENGTH - HDRBG_SEED_LENGTH - 1);
        hdrbg_seed(hd, reseeder, HDRBG_TV_RESEEDER_LENGTH);
        hdrbg_gen(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);
        hdrbg_gen(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);
        streamtobytes(tv, expected, HDRBG_TV_REQUEST_LENGTH);
        assert(memcmp(expected, observed, HDRBG_TV_REQUEST_LENGTH * sizeof *expected) == 0);
    }
    printf("\n");

    // With prediction resistance. Generating with prediction resistance is the
    // same as reinitialising and generating without prediction resistance, so
    // the code is similar.
    _ = fscanf(tv, "%zu", &count);
    for(size_t i = 0; i < count; ++i)
    {
        printf("Running test %zu/%zu with prediction resistance.\r", i + 1, count);
        streamtobytes(tv, seeder, HDRBG_TV_SEEDER_LENGTH);
        hdrbg_seed(hd, seeder, HDRBG_TV_SEEDER_LENGTH);
        memcpy(reseeder + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseeder);
        streamtobytes(tv, reseeder + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_RESEEDER_LENGTH - HDRBG_SEED_LENGTH - 1);
        hdrbg_seed(hd, reseeder, HDRBG_TV_RESEEDER_LENGTH);
        hdrbg_gen(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);
        memcpy(reseeder + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseeder);
        streamtobytes(tv, reseeder + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_RESEEDER_LENGTH - HDRBG_SEED_LENGTH - 1);
        hdrbg_seed(hd, reseeder, HDRBG_TV_RESEEDER_LENGTH);
        hdrbg_gen(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);
        streamtobytes(tv, expected, HDRBG_TV_REQUEST_LENGTH);
        assert(memcmp(expected, observed, HDRBG_TV_REQUEST_LENGTH * sizeof *expected) == 0);
    }
    printf("\n");

    fclose(tv);
    free(hd);
    printf("All tests passed.\n");
}
