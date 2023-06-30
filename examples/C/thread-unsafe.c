#include <hdrbg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

int main(void)
{
    hdrbg_new(false);
    uint8_t r_bytes[64];
    hdrbg_gen(NULL, false, r_bytes, 64);
    for(int i = 0; i < 64; ++i)
    {
        printf("%02"PRIx8, r_bytes[i]);
    }
    printf("\n");
    for(int i = 0; i < 4; ++i)
    {
        printf("%"PRIu64" ", hdrbg_rand(NULL));
    }
    for(int i = 0; i < 4; ++i)
    {
        printf("%Lf ", hdrbg_real(NULL));
    }
    printf("\n");
    hdrbg_delete(NULL);
}
