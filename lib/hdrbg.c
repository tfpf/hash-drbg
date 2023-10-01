#include <assert.h>
#include <inttypes.h>
#include <limits.h>
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

#if !(defined __STDC_NO_THREADS__ || defined _WIN32)
#include <threads.h>
static thread_local enum hdrbg_err_t
#else
static enum hdrbg_err_t
#endif
hdrbg_err = HDRBG_ERR_NONE;

#if defined _WIN32
#include <windows.h>
#include <bcrypt.h>
#elif defined __linux__ || defined __APPLE__
#include <sys/random.h>
#endif

#define HDRBG_SEED_LENGTH 55
#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_NONCE1_LENGTH 8
#define HDRBG_NONCE2_LENGTH 8
#define HDRBG_OUTPUT_LENGTH 32
#define HDRBG_REQUEST_LIMIT (1UL << 16)
#define HDRBG_RESEED_INTERVAL (1ULL << 48)

// Characteristics of test vectors.
#define HDRBG_TV_ENTROPY_LENGTH 32
#define HDRBG_TV_NONCE_LENGTH 16
#define HDRBG_TV_REQUEST_LENGTH 128

struct hdrbg_t
{
    // The first member is prepended with a byte whenever it is processed, so
    // keep an extra byte.
    uint8_t V[1 + HDRBG_SEED_LENGTH];
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
    for(; a_length > 0 && b_length > 0; --a_length, --b_length)
    {
        carry = a_bytes[a_length - 1] + carry + b_bytes[b_length - 1];
        a_bytes[a_length - 1] = carry;
        carry >>= 8;
    }
    for(; a_length > 0; --a_length)
    {
        carry += a_bytes[a_length - 1];
        a_bytes[a_length - 1] = carry;
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
    // Construct the data to be hashed in a sufficiently large array.
    size_t m_length = 5 + m_length_;
    uint8_t m_bytes[93];
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
 * Read bytes from a stream and store them in an array.
 *
 * @param fptr_ Stream to read bytes from. If `NULL`, a random device will be
 *     opened to read bytes, and then closed.
 * @param m_bytes Array to store the bytes in. (It must have sufficient space
 *     for `m_length` elements.)
 * @param m_length Number of bytes to store.
 *
 * @return Number of bytes stored.
 *****************************************************************************/
static size_t
streamtobytes(FILE *fptr_, uint8_t *m_bytes, size_t m_length)
{
    // The file will be specified only while testing.
    if(fptr_ != NULL)
    {
        size_t len = fread(m_bytes, sizeof *m_bytes, m_length, fptr_);
        if(len < m_length)
        {
            hdrbg_err = HDRBG_ERR_INSUFFICIENT_ENTROPY;
        }
        return len;
    }

    // During normal operation, the file won't be specified. Obtain bytes from
    // an entropy source.
#if defined _WIN32 && CHAR_BIT == 8
    NTSTATUS status = BCryptGenRandom(NULL, m_bytes, m_length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status != STATUS_SUCCESS)
    {
        hdrbg_err = HDRBG_ERR_NO_ENTROPY;
        return 0;
    }
    return m_length;
#elif (defined __linux__ || defined __APPLE__) && CHAR_BIT == 8
    ssize_t len = getrandom(m_bytes, m_length, 0);
    if(len < 0)
    {
        hdrbg_err = HDRBG_ERR_NO_ENTROPY;
        return 0;
    }
    if((size_t)len < m_length)
    {
        hdrbg_err = HDRBG_ERR_INSUFFICIENT_ENTROPY;
    }
    return len;
#else
    FILE *fptr = fopen("/dev/urandom");
    if(fptr == NULL)
    {
        hdrbg_err = HDRBG_ERR_NO_ENTROPY;
        return 0;
    }
    size_t len = fread(m_bytes, sizeof *m_bytes, m_length, fptr);
    if(len < m_length)
    {
        hdrbg_err = HDRBG_ERR_INSUFFICIENT_ENTROPY;
    }
    fclose(fptr);
    return len;
#endif
}

/******************************************************************************
 * Create and/or initialise (seed) an HDRBG object.
 *****************************************************************************/
struct hdrbg_t *
hdrbg_init(bool dma)
{
    struct hdrbg_t *hd = dma ? malloc(sizeof *hd) : &hdrbg;
    if(hd == NULL)
    {
        hdrbg_err = HDRBG_ERR_OUT_OF_MEMORY;
        return NULL;
    }
    uint8_t seedmaterial[HDRBG_SECURITY_STRENGTH + HDRBG_NONCE1_LENGTH + HDRBG_NONCE2_LENGTH];
    if(streamtobytes(NULL, seedmaterial, HDRBG_SECURITY_STRENGTH) < HDRBG_SECURITY_STRENGTH)
    {
        goto cleanup_hd;
    }
    memdecompose(seedmaterial + HDRBG_SECURITY_STRENGTH, HDRBG_NONCE1_LENGTH, time(NULL));
    memdecompose(seedmaterial + HDRBG_SECURITY_STRENGTH + HDRBG_NONCE1_LENGTH, HDRBG_NONCE2_LENGTH, seq_num++);
    hdrbg_seed(hd, seedmaterial, sizeof seedmaterial / sizeof *seedmaterial);
    return hd;

cleanup_hd:
    hdrbg_zero(hd);
    return NULL;
}

/******************************************************************************
 * Reinitialise (reseed) an HDRBG object.
 *****************************************************************************/
struct hdrbg_t *
hdrbg_reinit(struct hdrbg_t *hd)
{
    hd = hd == NULL ? &hdrbg : hd;
    uint8_t reseedmaterial[1 + HDRBG_SEED_LENGTH + HDRBG_SECURITY_STRENGTH] = {0x01U};
    memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
    if(streamtobytes(NULL, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_SECURITY_STRENGTH) < HDRBG_SECURITY_STRENGTH)
    {
        return NULL;
    }
    hdrbg_seed(hd, reseedmaterial, sizeof reseedmaterial / sizeof *reseedmaterial);
    return hd;
}

/******************************************************************************
 * Generate cryptographically secure pseudorandom bytes.
 *****************************************************************************/
int
hdrbg_fill(struct hdrbg_t *hd, bool prediction_resistance, uint8_t *r_bytes, int long unsigned r_length)
{
    if(r_length > HDRBG_REQUEST_LIMIT)
    {
        hdrbg_err = HDRBG_ERR_INVALID_REQUEST_FILL;
        return -1;
    }
    hd = hd == NULL ? &hdrbg : hd;
    if(prediction_resistance || hd->gen_count == HDRBG_RESEED_INTERVAL)
    {
        if(hdrbg_reinit(hd) == NULL)
        {
            return -1;
        }
    }
    if(r_length > 0)
    {
        hash_gen(hd->V + 1, r_bytes, r_length);
    }

    // Mutate the state.
    hd->V[0] = 0x03U;
    uint8_t tmp[HDRBG_OUTPUT_LENGTH];
    sha256(hd->V, HDRBG_SEED_LENGTH + 1, tmp);
    uint8_t gen_count[8];
    memdecompose(gen_count, 8, ++hd->gen_count);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, tmp, HDRBG_OUTPUT_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, hd->C, HDRBG_SEED_LENGTH);
    add_accumulate(hd->V + 1, HDRBG_SEED_LENGTH, gen_count, 8);
    return 0;
}

/******************************************************************************
 * Helper for `hdrbg_rand`.
 *
 * @param hd
 * @param r
 *
 * @return On success: 0. On failure: -1.
 *****************************************************************************/
static int
hdrbg_rand_(struct hdrbg_t *hd, uint64_t *r)
{
    uint8_t value[8];
    if(hdrbg_fill(hd, false, value, 8) < 0)
    {
        return -1;
    }
    *r = memcompose(value, 8);
    return 0;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom number.
 *****************************************************************************/
uint64_t
hdrbg_rand(struct hdrbg_t *hd)
{
    uint64_t r;
    if(hdrbg_rand_(hd, &r) == -1)
    {
        return -1;
    }
    return r;
}

/******************************************************************************
 * Helper for `hdrbg_uint`.
 *
 * @param hd
 * @param modulus
 * @param r
 *
 * @return On success: 0. On failure: -1.
 *****************************************************************************/
static int
hdrbg_uint_(struct hdrbg_t *hd, uint64_t modulus, uint64_t *r)
{
    if(modulus == 0)
    {
        hdrbg_err = HDRBG_ERR_INVALID_REQUEST_UINT;
        return -1;
    }
    uint64_t upper = 0xFFFFFFFFFFFFFFFFU - 0xFFFFFFFFFFFFFFFFU % modulus;
    do
    {
        if(hdrbg_rand_(hd, r) == -1)
        {
            return -1;
        }
    }
    while(*r >= upper);
    *r %= modulus;
    return 0;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom residue.
 *****************************************************************************/
uint64_t
hdrbg_uint(struct hdrbg_t *hd, uint64_t modulus)
{
    uint64_t r;
    if(hdrbg_uint_(hd, modulus, &r) == -1)
    {
        return -1;
    }
    return r;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom residue offset.
 *****************************************************************************/
int64_t
hdrbg_span(struct hdrbg_t *hd, int64_t left, int64_t right)
{
    if(left >= right)
    {
        hdrbg_err = HDRBG_ERR_INVALID_REQUEST_SPAN;
        return -1;
    }
    uint64_t uleft = left;
    uint64_t uright = right;
    uint64_t modulus = uright - uleft;
    uint64_t r;
    if(hdrbg_uint_(hd, modulus, &r) == -1)
    {
        return -1;
    }
    r += uleft;

    // According to the C standard, implicit conversion of an unsigned integer
    // into a signed integer when the type of the latter cannot represent the
    // value of the former results in implementation-defined behaviour. Hence,
    // type-pun the value, exploiting the fact that fixed-width integers use
    // two's complement representation.
    return *(int64_t *)&r;
}

/******************************************************************************
 * Generate a cryptographically secure pseudorandom fraction.
 *****************************************************************************/
double long
hdrbg_real(struct hdrbg_t *hd)
{
    uint64_t r;
    if(hdrbg_rand_(hd, &r) == -1)
    {
        return -1.0L;
    }
    return (double long)r / 0xFFFFFFFFFFFFFFFFU;
}

/******************************************************************************
 * Advance the state of an HDRBG object.
 *****************************************************************************/
int
hdrbg_drop(struct hdrbg_t *hd, int long long count)
{
    while(count-- > 0)
    {
        if(hdrbg_fill(hd, false, NULL, 0) < 0)
        {
            return -1;
        }
    }
    return 0;
}

/******************************************************************************
 * Clear (zero) and/or destroy an HDRBG object.
 *****************************************************************************/
void
hdrbg_zero(struct hdrbg_t *hd)
{
    if(hd == NULL || hd == &hdrbg)
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
hdrbg_tests_pr(struct hdrbg_t *hd, bool prediction_resistance, FILE *tv)
{
    for(int i = 0; i < 60; ++i)
    {
        // Initialise.
        uint8_t seedmaterial[HDRBG_TV_ENTROPY_LENGTH + HDRBG_TV_NONCE_LENGTH];
        streamtobytes(tv, seedmaterial, HDRBG_TV_ENTROPY_LENGTH + HDRBG_TV_NONCE_LENGTH);
        hdrbg_seed(hd, seedmaterial, sizeof seedmaterial / sizeof *seedmaterial);

        // Reinitialise.
        uint8_t reseedmaterial[1 + HDRBG_SEED_LENGTH + HDRBG_TV_ENTROPY_LENGTH] = {0x01U};
        memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
        streamtobytes(tv, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_ENTROPY_LENGTH);
        hdrbg_seed(hd, reseedmaterial, sizeof reseedmaterial / sizeof *reseedmaterial);

        // Generate.
        uint8_t observed[HDRBG_TV_REQUEST_LENGTH];
        hdrbg_fill(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);

        // Reinitialise.
        if(prediction_resistance)
        {
            memcpy(reseedmaterial + 1, hd->V + 1, HDRBG_SEED_LENGTH * sizeof *reseedmaterial);
            streamtobytes(tv, reseedmaterial + 1 + HDRBG_SEED_LENGTH, HDRBG_TV_ENTROPY_LENGTH);
            hdrbg_seed(hd, reseedmaterial, sizeof reseedmaterial / sizeof *reseedmaterial);
        }

        // Generate.
        hdrbg_fill(hd, false, observed, HDRBG_TV_REQUEST_LENGTH);

        uint8_t expected[HDRBG_TV_REQUEST_LENGTH];
        streamtobytes(tv, expected, HDRBG_TV_REQUEST_LENGTH);
        assert(memcmp(expected, observed, HDRBG_TV_REQUEST_LENGTH * sizeof *expected) == 0);
    }
}

/******************************************************************************
 * Verify that the implementation works as specified. This function is meant
 * for testing purposes only; using it outside the test environment may result
 * in undefined behaviour.
 *
 * @param hd HDRBG object to use. If `NULL`, the internal HDRBG object will be
 *     used.
 * @param tv Test vectors file. This is of type `void *` rather than `FILE *`
 *     because I didn't want to include another C header in the header of this
 *     library.
 *****************************************************************************/
void
hdrbg_tests(struct hdrbg_t *hd, void *tv)
{
    hd = hd == NULL ? &hdrbg : hd;
    hdrbg_tests_pr(hd, false, tv);
    hdrbg_tests_pr(hd, true, tv);
}
