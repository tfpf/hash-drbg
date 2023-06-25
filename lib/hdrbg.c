#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "hdrbg.h"
#include "sha.h"

struct hdrbg_t
{
    uint8_t V[56];
    uint8_t C[56];
    uint64_t count;
    uint32_t nonce;
};

void hdrbg_init(struct hdrbg_t *hd)
{
    uint8_t seed_material[36];

    // Obtain 32 bytes of entropy.
    FILE *rd = fopen("/dev/urandom", "rb");
    for(int i = 0; i < 8; ++i)
    {
        uint32_t value;
        fscanf(rd, "%"PRIu32, &value);
        for(int j = 0; j < 4; ++j)
        {
            seed_material[(i << 2) + j] = value;
            value >>= 8;
        }
    }
    fclose(rd);

    // Obtain a 4-byte number.
    uint32_t nonce = 0;
    time_t now = time(NULL);
    char unsigned *n_iter = &now;
    for(size_t i = 0; i < sizeof now; ++i, ++n_iter)
    {
        // XOR rather than OR because `char unsigned` need not be 8 bits wide.
        nonce = nonce << 8 ^ *n_iter;
    }
}
