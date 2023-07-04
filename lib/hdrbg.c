#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

#ifndef __STDC_NO_ATOMICS__
#include <stdatomic.h>
static atomic_ullong
#else
static int long long unsigned
#endif
seq_num = 0;

#ifndef __STDC_NO_THREADS__
#include <threads.h>
static thread_local enum hdrbg_err_t
#else
static enum hdrbg_err_t
#endif
hdrbg_err = HDRBG_ERR_NONE;

#define HDRBG_SEED_LENGTH 55
#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_NONCE1_LENGTH 8
#define HDRBG_NONCE2_LENGTH 8
#define HDRBG_SEEDMATERIAL_LENGTH (HDRBG_SECURITY_STRENGTH + HDRBG_NONCE1_LENGTH + HDRBG_NONCE2_LENGTH)
#define HDRBG_RESEEDMATERIAL_LENGTH (1 + HDRBG_SEED_LENGTH + HDRBG_SECURITY_STRENGTH)
#define HDRBG_OUTPUT_LENGTH 32
#define HDRBG_REQUEST_LIMIT (1ULL << 16)
#define HDRBG_RESEED_INTERVAL (1ULL << 48)

// Characteristics of test vectors.
#define HDRBG_TV_ENTROPY_LENGTH 32
#define HDRBG_TV_NONCE_LENGTH 16
#define HDRBG_TV_SEEDMATERIAL_LENGTH (HDRBG_TV_ENTROPY_LENGTH + HDRBG_TV_NONCE_LENGTH)
#define HDRBG_TV_RESEEDMATERIAL_LENGTH (1 + HDRBG_SEED_LENGTH + HDRBG_TV_ENTROPY_LENGTH)
#define HDRBG_TV_REQUEST_LENGTH 128

struct hdrbg_t
{
    // The first member is prepended with a byte whenever it is processed, so
    // keep an extra byte.
    uint8_t V[HDRBG_SEED_LENGTH + 1];
    uint8_t C[HDRBG_SEED_LENGTH];
    uint64_t gen_count;
};
static struct hdrbg_t
hdrbg;

/******************************************************************************
 * Obtain the error status.
 *****************************************************************************/
enum hdrbg_err_t
hdrbg_err_get(void)
{
    enum hdrbg_err_t err = hdrbg_err;
    hdrbg_err = HDRBG_ERR_NONE;
    return err;
}

/******************************************************************************
 * Add two numbers. Overwrite the first number with the result, disregarding
 * any carried bytes.
 *
 * @param a_bytes Array of bytes of the first number in big-endian order.
 * @param a_length Number of bytes of the first number.
 * @param b_bytes Array of bytes of the second number in big-endian order.
 * @param b_length Number of bytes of the second number. Must be less than or
 *     equal to `a_length`.
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
    for(size_t i = 1; i <= iterations; ++i)
    {
        m_bytes[0] = i;
        uint8_t tmp[HDRBG_OUTPUT_LENGTH];
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
    for(size_t i = 0; i < iterations; ++i)
    {
        uint8_t tmp[HDRBG_OUTPUT_LENGTH];
        sha256(m_bytes, HDRBG_SEED_LENGTH, tmp);
        size_t len = h_length >= HDRBG_OUTPUT_LENGTH ? HDRBG_OUTPUT_LENGTH : h_length;
        memcpy(h_bytes, tmp, len * sizeof *h_bytes);
        h_length -= len;
        h_bytes += len;
        uint8_t one = 1;
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
    hd->gen_count = 0;
}

/******************************************************************************
 * Convert an unsigned integer into a signed integer in a safe manner.
 * (According to the C standard, implicit conversion of an unsigned integer
 * into a signed integer when the type of the latter cannot represent the value
 * of the former results in implementation-defined behaviour.)
 *
 * @param ui Unsigned integer.
 *
 * @return Signed integer with value congruent to `ui` modulo 2 ** 64.
 *****************************************************************************/
static int64_t
utos(uint64_t ui)
{
    if(ui <= 0x7FFFFFFFFFFFFFFFU)
    {
        return ui;
    }
    int64_t si = ui - 0x8000000000000000U;
    return si - (int64_t)0x8000000000000000;
}

/******************************************************************************
 * Read bytes from a stream and store them in an array.
 *
 * @param fptr_ Stream to read bytes from. If `NULL`, a random device will be
 *     opened to read bytes, and then closed.
 * @param m_bytes Array to store the bytes in. (It must have sufficient space
 *     for `m_length` elements.)
 * @param m_length Number of bytes to store.
 *
 * @return Number of bytes stored. Can be different from `m_length` if an error
 *     occurs.
 *****************************************************************************/
static size_t
streamtobytes(FILE *fptr_, uint8_t *m_bytes, size_t m_length)
{
    FILE *fptr = fptr_ == NULL ? fopen("/dev/urandom", "rb") : fptr_;
    size_t len = fread(m_bytes, sizeof *m_bytes, m_length, fptr);
    if(fptr_ == NULL)
    {
        fclose(fptr);
    }
    return len;
}

/******************************************************************************
 * Create and/or initialise (seed) an HDRBG object.
 *****************************************************************************/
struct hdrbg_t *
hdrbg_init(bool dma)
{
    struct hdrbg_t *hd = dma ? malloc(sizeof *hd) : &hdrbg;
    uint8_t seedmaterial[HDRBG_SEEDMATERIAL_LENGTH];
    uint8_t *s_iter = seedmaterial;
    s_iter += streamtobytes(NULL, s_iter, HDRBG_SECURITY_STRENGTH);
    s_iter += memdecompose(s_iter, HDRBG_NONCE1_LENGTH, time(NULL));
    s_iter += memdecompose(s_iter, HDRBG_NONCE2_LENGTH, seq_num++);
    hdrbg_seed(hd, seedmaterial, sizeof seedmaterial / sizeof *seedmaterial);
    return dma ? hd : NULL;
}

/******************************************************************************
 * Reinitialise (reseed) an HDRBG object.
 *****************************************************************************/
void
hdrbg_reinit(struct hdrbg_t *hd)
{
    hd = hd == NULL ? &hdrbg : hd;
    uint8_t reseedmaterial[HDRBG_RESEEDMATERIAL_LENGTH] = {0x01U};
    memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
    streamtobytes(NULL, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_SECURITY_STRENGTH);
    hdrbg_seed(hd, reseedmaterial, sizeof reseedmaterial / sizeof *reseedmaterial);
}

/******************************************************************************
 * Generate cryptographically secure pseudorandom bytes.
 *****************************************************************************/
bool
hdrbg_fill(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, size_t r_length)
{
    if(r_length > HDRBG_REQUEST_LIMIT)
    {
        return false;
    }
    hd = hd == NULL ? &hdrbg : hd;
    if(prediction_resistance || hd->gen_count == HDRBG_RESEED_INTERVAL)
    {
        hdrbg_reinit(hd);
    }
    hash_gen(hd->V + 1, r_bytes, r_length);

    // Mutate the state.
    hd->V[0] = 0x03U;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    sha256(hd->V, HDRBG_SEED_LENGTH + 1, tmp);
    uint8_t gen_count[8];
    memdecompose(gen_count, 8, ++hd->gen_count);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, tmp, HDRBG_OUTPUT_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, hd->C, HDRBG_SEED_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, gen_count, 8);
    return true;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom number.
 *****************************************************************************/
uint64_t
hdrbg_rand(struct hdrbg_t *hd)
{
    uint8_t value[8];
    hdrbg_fill(hd, false, value, 8);
    return memcompose(value, 8);
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom residue.
 *****************************************************************************/
uint64_t
hdrbg_uint(struct hdrbg_t *hd, uint64_t modulus)
{
    uint64_t upper = 0xFFFFFFFFFFFFFFFFU - 0xFFFFFFFFFFFFFFFFU % modulus;
    uint64_t r;
    do
    {
        r = hdrbg_rand(hd);
    }
    while(r >= upper);
    return r % modulus;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom residue offset.
 *****************************************************************************/
int64_t
hdrbg_span(struct hdrbg_t *hd, int64_t left, int64_t right)
{
    uint64_t uleft = left;
    uint64_t uright = right;
    uint64_t modulus = uright - uleft;
    uint64_t r = hdrbg_uint(hd, modulus);
    return utos(r + uleft);
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom fraction.
 *****************************************************************************/
double long
hdrbg_real(struct hdrbg_t *hd)
{
    return (double long)hdrbg_rand(hd) / 0xFFFFFFFFFFFFFFFFU;
}

/******************************************************************************
 * Clear (zero) and/or destroy an HDRBG object.
 *****************************************************************************/
void
hdrbg_zero(struct hdrbg_t *hd)
{
    if(hd == NULL)
    {
        memclear(&hdrbg, sizeof hdrbg);
        return;
    }
    memclear(hd, sizeof *hd);
    free(hd);
}

/******************************************************************************
 * Display the given data in hexadecimal form.
 *****************************************************************************/
void
hdrbg_dump(uint8_t const *m_bytes, size_t m_length)
{
    while(m_length-- > 0)
    {
        fprintf(stdout, "%02"PRIx8, *m_bytes++);
    }
    fprintf(stdout, "\n");
}

/******************************************************************************
 * Test a particular HDRBG object for a given prediction resistance setting.
 *
 * The test sequence for no prediction resistance is: initialise, reinitialise,
 * generate and generate. That for prediction resistance is: initialise,
 * generate and generate. A request for prediction resistance means that the
 * HDRBG object should be reinitialised before generation, so the latter
 * sequence is equivalent to: initialise, reinitialise, generate, reinitialise
 * and generate without prediction resistance.
 *
 * There are a total of 60 tests without prediction resistance and 60 tests
 * with prediction resistance.
 *
 * @param hd HDRBG object.
 * @param prediction_resistance Prediction resistance.
 * @param tv Test vectors file.
 *****************************************************************************/
static void
hdrbg_test_obj_pr(struct hdrbg_t *hd, bool prediction_resistance, FILE *tv)
{
    for(int i = 0; i < 60; ++i)
    {
        // Initialise.
        uint8_t seedmaterial[HDRBG_TV_SEEDMATERIAL_LENGTH];
        streamtobytes(tv, seedmaterial, HDRBG_TV_SEEDMATERIAL_LENGTH);
        hdrbg_seed(hd, seedmaterial, HDRBG_TV_SEEDMATERIAL_LENGTH);

        // Reinitialise.
        uint8_t reseedmaterial[HDRBG_TV_RESEEDMATERIAL_LENGTH] = {0x01U};
        memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
        streamtobytes(tv, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_ENTROPY_LENGTH);
        hdrbg_seed(hd, reseedmaterial, HDRBG_TV_RESEEDMATERIAL_LENGTH);

        // Generate.
        uint8_t observed[HDRBG_TV_REQUEST_LENGTH];
        hdrbg_fill(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);

        // Reinitialise.
        if(prediction_resistance)
        {
            memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
            streamtobytes(tv, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_ENTROPY_LENGTH);
            hdrbg_seed(hd, reseedmaterial, HDRBG_TV_RESEEDMATERIAL_LENGTH);
        }

        // Generate.
        hdrbg_fill(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);

        uint8_t expected[HDRBG_TV_REQUEST_LENGTH];
        streamtobytes(tv, expected, HDRBG_TV_REQUEST_LENGTH);
        assert(memcmp(expected, observed, HDRBG_TV_REQUEST_LENGTH * sizeof *expected) == 0);
    }
}

/******************************************************************************
 * Test a particular HDRBG object.
 *
 * @param hd HDRBG object.
 * @param tv Test vectors file.
 *****************************************************************************/
static void
hdrbg_test_obj(struct hdrbg_t *hd, FILE *tv)
{
    hdrbg_test_obj_pr(hd, false, tv);
    hdrbg_test_obj_pr(hd, true, tv);
    for(int i = 0; i < 30000; ++i)
    {
        int64_t left = utos(hdrbg_rand(hd));
        int64_t right = utos(hdrbg_rand(hd));
        if(left < right)
        {
            int64_t middle = hdrbg_span(hd, left, right);
            assert(left <= middle && middle < right);
        }
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
    printf("Testing the internal HDRBG object.\n");
    FILE *tv = fopen("Hash_DRBG.dat", "rb");
    hdrbg_test_obj(&hdrbg, tv);
    printf("All tests passed.\n");

    printf("Testing a dynamically-allocated HDRBG object.\n");
    rewind(tv);
    struct hdrbg_t *hd = malloc(sizeof *hd);
    hdrbg_test_obj(hd, tv);
    free(hd);
    fclose(tv);
    printf("All tests passed.\n");
}
