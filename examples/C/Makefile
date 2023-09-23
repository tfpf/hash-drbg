CFLAGS = $(shell pkg-config --cflags hdrbg)
LDFLAGS = $(shell pkg-config --libs-only-L hdrbg)
LDLIBS = $(shell pkg-config --libs-only-l hdrbg)

Sources = $(wildcard *.c)
Executables = $(Sources:.c=)

.PHONY: all

all: $(Executables)
