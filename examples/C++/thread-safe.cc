#include <cinttypes>
#include <hdrbg.h>
#include <iostream>

int main(void)
{
    hdrbg_t *hd = hdrbg_init(true);
    std::uint8_t r_bytes[64];
    hdrbg_fill(hd, false, r_bytes, 64);
    hdrbg_dump(r_bytes, 64);

    for(int i = 0; i < 4; ++i)
    {
        std::cout << hdrbg_rand(hd) << ' ';
    }
    for(int i = 0; i < 4; ++i)
    {
        std::cout << hdrbg_real(hd) << ' ';
    }
    std::cout << '\n';
    hdrbg_zero(hd);
}
