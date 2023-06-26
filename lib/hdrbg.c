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
    uint64_t seq_num;
};

/******************************************************************************
 * Create and/or initialise an HDRBG object with 256-bit security strength.
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
        hd->seq_num = 0;
    }
    ++hd->seq_num;

    uint8_t seed_material[44];
    uint8_t *s_iter = seed_material;

    // Obtain 32 bytes of entropy.
    FILE *rd = fopen("/dev/urandom", "rb");
    fread(s_iter, sizeof *s_iter, 32, rd);
    fclose(rd);
    s_iter += 32;

    // Obtain a 4-byte timestamp.
    uint32_t now = time(NULL);
    for(int i = 0; i < 4; ++i)
    {
        *s_iter++ = now;
        now >>= 8;
    }

    // Obtain an 8-byte sequence number.
    uint64_t seq_num = hd->seq_num;
    for(int i = 0; i < 8; ++i)
    {
        *s_iter++ = seq_num;
        seq_num >>= 8;
    }
    memdump(seed_material, sizeof seed_material / sizeof *seed_material);
    return hd;
}
