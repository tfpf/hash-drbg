#include <algorithm>
#include <chrono>
#include <cstdio>
#include <hdrbg.h>

#define benchmark(function, iterations)  \
{  \
    auto delay = std::chrono::microseconds::max();  \
    for(int i = 0; i < 32; ++i)  \
    {  \
        auto begin = std::chrono::high_resolution_clock::now();  \
        for(int i = 0; i < iterations; ++i)  \
        {  \
            function(0);  \
        }  \
        auto end = std::chrono::high_resolution_clock::now();  \
        auto delay_ = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);  \
        delay = std::min(delay, delay_);  \
    }  \
    auto result = delay.count() / static_cast<double>(iterations);  \
    std::printf("%20s %8.2lf µs\n", #function, result);  \
}

/******************************************************************************
 * Main function.
 *****************************************************************************/
int main(void)
{
    benchmark(hdrbg_init, 100)
    benchmark(hdrbg_rand, 800)
    benchmark(hdrbg_real, 800)
}
