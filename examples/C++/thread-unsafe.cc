#include <cinttypes>
#include <cstddef>
#include <hdrbg.h>
#include <iostream>

int
main(void)
{
    hdrbg_init(false);
    std::uint8_t r_bytes[64];
    hdrbg_fill(NULL, false, r_bytes, 64);
    hdrbg_dump(r_bytes, 64);

    for (int i = 0; i < 4; ++i)
    {
        std::cout << hdrbg_rand(NULL) << ' ';
    }
    for (int i = 0; i < 4; ++i)
    {
        std::cout << hdrbg_real(NULL) << ' ';
    }
    std::cout << '\n';
    hdrbg_zero(NULL);
}
