#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>

/******************************************************************************
 * Display the given data in hexadecimal form.
 *
 * @param bytes Array of numbers representing the big-endian data to display.
 * @param length Numer of elements in the array.
 *****************************************************************************/
void
dump(uint8_t const *bytes, size_t length)
{
    for(size_t i = 0; i < length; ++i)
    {
        fprintf(stderr, "%02"PRIX8, bytes[i]);
    }
    fprintf(stderr, "\n");
}
