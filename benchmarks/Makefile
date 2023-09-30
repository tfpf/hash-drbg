CXXFLAGS = -O3 -std=c++17 -Wall -Wextra $(shell pkg-config --cflags hdrbg openssl)
LDFLAGS = $(shell pkg-config --libs-only-L hdrbg openssl)
LDLIBS = $(shell pkg-config --libs-only-l hdrbg openssl)

benchmarks:
