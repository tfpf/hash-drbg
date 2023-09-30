CFLAGS = $(shell pkg-config --cflags hdrbg openssl)
LDFLAGS = $(shell pkg-config --libs-only-L hdrbg openssl)
LDLIBS = $(shell pkg-config --libs-only-l hdrbg openssl)

Sources = $(wildcard *.c)
Executables = $(Sources:.c=)

.PHONY: all

all: $(Executables)
