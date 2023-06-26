#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/******************************************************************************
 * Display the given data in hexadecimal form.
 *
 * @param bytes Array of numbers representing the big-endian data to display.
 * @param length Numer of elements in the array.
 *****************************************************************************/
void
memdump(uint8_t const *bytes, size_t length)
{
    for(size_t i = 0; i < length; ++i)
    {
        fprintf(stderr, "%02"PRIX8, bytes[i]);
    }
    fprintf(stderr, "\n");
}

/******************************************************************************
 * Clear memory. Since this file is compiled separately, this function
 * shouldn't be optimised out.
 *
 * @param ptr
 * @param size
 *****************************************************************************/
void
memclear(void *ptr, size_t size)
{
    memset(ptr, 0, size);
}
