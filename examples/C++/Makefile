CFLAGS = $(shell pkg-config --cflags hdrbg openssl)
LDFLAGS = $(shell pkg-config --libs-only-L hdrbg openssl)
LDLIBS = $(shell pkg-config --libs-only-l hdrbg openssl)

Sources = $(wildcard *.cc)
Executables = $(Sources:.cc=)

.PHONY: all

all: $(Executables)
