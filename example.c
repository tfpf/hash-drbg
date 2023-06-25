#include <stdio.h>
#include <stdlib.h>

#include "hdrbg.h"
#include "misc.h"
#include "sha.h"

int main(void)
{
    uint8_t message[1000];
    for(size_t i = 0; i < 1000; ++i)
    {
        message[i] = 0x61U;
        sha256(message, i, NULL);
    }
    void *p = hdrbg_init(NULL);
    hdrbg_init(p);
}
