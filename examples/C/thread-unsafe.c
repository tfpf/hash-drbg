#include <hdrbg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

int main(void)
{
    uint8_t r_bytes[64];
    hdrbg_new(false);
    for(int i = 0; i < 4; ++i)
    {
        hdrbg_gen(NULL, false, r_bytes, 64);
        for(int i = 0; i < 64; ++i)
        {
            printf("%02"PRIx8, r_bytes[i]);
        }
        printf("\n");
    }
    hdrbg_delete(NULL);
}
