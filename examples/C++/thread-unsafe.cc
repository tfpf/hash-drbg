#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <hdrbg.h>

int main(void)
{
    hdrbg_new(false);
    std::uint8_t r_bytes[64];
    hdrbg_gen(NULL, false, r_bytes, 64);
    for(int i = 0; i < 64; ++i)
    {
        std::printf("%02" PRIx8, r_bytes[i]);
    }
    std::printf("\n");
    for(int i = 0; i < 4; ++i)
    {
        std::printf("%" PRIu64 " ", hdrbg_rand(NULL));
    }
    std::printf("\n");
    hdrbg_delete(NULL);
}
