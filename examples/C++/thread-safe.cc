#include <cinttypes>
#include <cstdio>
#include <hdrbg.h>

int main(void)
{
    hdrbg_t *hd = hdrbg_init(true);
    std::uint8_t r_bytes[64];
    hdrbg_fill(hd, false, r_bytes, 64);
    hdrbg_dump(r_bytes, 64);

    for(int i = 0; i < 4; ++i)
    {
        std::printf("%" PRIu64 " ", hdrbg_rand(hd));
    }
    for(int i = 0; i < 4; ++i)
    {
        std::printf("%Lf ", hdrbg_real(hd));
    }
    std::printf("\n");
    hdrbg_zero(hd);
}
