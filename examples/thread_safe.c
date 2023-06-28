#include <hdrbg.h>
#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    uint8_t r_bytes[64];
    struct hdrbg_t *hd = hdrbg_new();
    for(int i = 0; i < 4; ++i)
    {
        hdrbg_gen(hd, false, r_bytes, 64);
        for(int i = 0; i < 64; ++i)
        {
            printf("%02"PRIx8, r_bytes[i]);
        }
        printf("\n");
    }
    hdrbg_delete(hd);
}
