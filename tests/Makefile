CFLAGS = -std=c17 -O2 -Wall -Wextra $(shell pkg-config --cflags hdrbg openssl)
LDFLAGS = $(shell pkg-config --libs-only-L hdrbg openssl)
LDLIBS = $(shell pkg-config --libs-only-l hdrbg openssl)

tests:
