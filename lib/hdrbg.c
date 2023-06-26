#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

struct hdrbg_t
{
    uint8_t V[56];
    uint8_t C[56];
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

    uint8_t seed_material[44];
    uint8_t *s_iter = seed_material;

    // Obtain 32 bytes of entropy.
    FILE *rd = fopen("/dev/urandom", "rb");
    fread(s_iter, sizeof *s_iter, 32, rd);
    fclose(rd);
    s_iter += 32;

    // Obtain a 4-byte timestamp.
    uint32_t now = time(NULL);
    s_iter += memdecompose(s_iter, 4, now);

    // Obtain an 8-byte sequence number.
    s_iter += memdecompose(s_iter, 8, hd->seed_count);
    memdump(seed_material, sizeof seed_material / sizeof *seed_material);
    return hd;
}
