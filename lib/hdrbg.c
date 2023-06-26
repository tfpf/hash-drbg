#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

// All numbers are in bytes.
#define HDRBG_SECURITY_STRENGTH 32
#define HDRBG_SEED_LENGTH 55

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
    memdump(seeder, sizeof seeder / sizeof *seeder);

    // Obtain the seed.
    hash_df(seeder, sizeof seeder / sizeof *seeder, hd->V + 1, HDRBG_SEED_LENGTH);
    return hd;
}

/******************************************************************************
 * Use a hash function to transform the input bytes into the required number of
 * output bytes.
 *
 * @param m_bytes Input bytes.
 * @param m_length Number of input bytes.
 * @param h_bytes Array to store the output bytes in. (It must have enough
 *     space to store the required number of output bytes.)
 * @param h_length Number of output bytes required.
 *****************************************************************************/
void
hash_df(uint8_t const *m_bytes, size_t m_length, uint8_t *h_bytes, size_t h_length)
{
}
