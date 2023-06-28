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
    while(length-- > 0)
    {
        fprintf(stderr, "%02"PRIx8, *bytes++);
    }
    fprintf(stderr, "\n");
}

/******************************************************************************
 * Clear memory. Since this file is compiled separately, this function
 * shouldn't be optimised out when called just before freeing the memory.
 *
 * @param ptr
 * @param size
 *****************************************************************************/
void
memclear(void *ptr, size_t size)
{
    memset(ptr, 0, size);
}

/******************************************************************************
 * Compose some bytes into a number.
 *
 * @param addr Starting address of the bytes.
 * @param length Number of bytes to process. At most 8.
 *
 * @return Bytes interpreted as a big-endian integer.
 *****************************************************************************/
uint64_t
memcompose(uint8_t const *addr, size_t length)
{
    uint64_t value = 0;
    while(length-- > 0)
    {
        value = value << 8 | *addr++;
    }
    return value;
}

/******************************************************************************
 * Decompose the bytes of a number.
 *
 * @param addr Starting address from which the bytes of the number will be
 *     written in big-endian order.
 * @param length Number of bytes to process. At most 8.
 * @param value Number to be decomposed.
 *
 * @return Number of bytes processed (`length`).
 *****************************************************************************/
size_t
memdecompose(uint8_t *addr, size_t length, uint64_t value)
{
    for(size_t i = 0; i < length; ++i)
    {
        addr[length - 1 - i] = value;
        value >>= 8;
    }
    return length;
}
