CFLAGS = -std=c11 -O2 -Wall -Wextra -I./include -fPIC -fstrict-aliasing

Sources = $(wildcard lib/*.c)
Objects = $(Sources:.c=.o)
Library = lib/hdrbg.so


example: $(Objects) example.c

$(Library): $(Objects)
	$(CC) $(CFLAGS) -shared -o $@ $^
