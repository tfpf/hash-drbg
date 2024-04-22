#include <hdrbg.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

int
main(void)
{
    struct hdrbg_t *hd = hdrbg_init(true);
    uint8_t r_bytes[64];
    hdrbg_fill(hd, false, r_bytes, 64);
    hdrbg_dump(r_bytes, 64);

    for (int i = 0; i < 4; ++i)
    {
        printf("%" PRIu64 " ", hdrbg_rand(hd));
    }
    for (int i = 0; i < 4; ++i)
    {
        printf("%Lf ", hdrbg_real(hd));
    }
    printf("\n");
    hdrbg_zero(hd);
}
