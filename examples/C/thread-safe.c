#include <hdrbg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

int main(void)
{
    struct hdrbg_t *hd = hdrbg_new(true);
    uint8_t r_bytes[64];
    hdrbg_gen(hd, false, r_bytes, 64);
    for(int i = 0; i < 64; ++i)
    {
        printf("%02"PRIx8, r_bytes[i]);
    }
    printf("\n");
    for(int i = 0; i < 4; ++i)
    {
        printf("%"PRIu64" ", hdrbg_rand(hd));
    }
    printf("\n");
    hdrbg_delete(hd);
}
