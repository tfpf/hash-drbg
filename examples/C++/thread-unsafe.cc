#include <cinttypes>
#include <cstddef>
#include <cstdio>
#include <hdrbg.h>

int main(void)
{
    std::uint8_t r_bytes[64];
    hdrbg_new(false);
    for(int i = 0; i < 4; ++i)
    {
        hdrbg_gen(NULL, false, r_bytes, 64);
        for(int i = 0; i < 64; ++i)
        {
            std::printf("%02" PRIx8, r_bytes[i]);
        }
        std::printf("\n");
    }
    hdrbg_delete(NULL);
}
