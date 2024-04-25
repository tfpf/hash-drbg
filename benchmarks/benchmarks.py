#! /usr/bin/env python3

import math
import time
import timeit

import hdrbg


def benchmark(stmt, number, passes=32):
    delay = math.inf
    for _ in range(passes):
        delay_ = timeit.timeit(stmt=stmt, number=number, timer=time.perf_counter_ns)
        delay = min(delay, delay_)
    result = delay / number / 1000
    print(f"{stmt.__name__:>20} {result:8.2f} µs")


def main():
    """Main function."""
    benchmark(hdrbg._init, 100)
    benchmark(hdrbg._reinit, 100)
    benchmark(hdrbg.rand, 800)
    benchmark(hdrbg.real, 800)


if __name__ == "__main__":
    main()
