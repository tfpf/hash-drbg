#include <stdio.h>
#include <stdlib.h>

#include "extras.h"
#include "hdrbg.h"
#include "sha.h"

int main(void)
{
    uint8_t message[1000];
    for(size_t i = 0; i < 1000; ++i)
    {
        message[i] = 0x61U;
    }
    for(size_t i = 0; i < 1000; ++i)
    {
        sha256(message, 1000, message);  // 08F94425E2C2CB064A9843285868D6A8207A2C9AEA011386053BF481DD14FFF2
    }
    memdump(sha256(message, 1000, NULL), 32);
    void *hd = hdrbg_new();
    hdrbg_renew(hd);
    hdrbg_delete(hd);
}
