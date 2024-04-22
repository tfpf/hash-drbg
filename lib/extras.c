#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include "extras.h"

/******************************************************************************
 * Clear memory. Since this file is compiled separately, this function
 * shouldn't be optimised out when called just before freeing the memory.
 *
 * @param ptr
 * @param sz
 *****************************************************************************/
void
memclear(void *ptr, size_t sz)
{
    memset(ptr, 0, sz);
}

/******************************************************************************
 * Compose some bytes into a number.
 *
 * @param m_bytes Array of bytes.
 * @param m_length Number of bytes to process. At most 8.
 *
 * @return Bytes interpreted as a big-endian integer.
 *****************************************************************************/
uint64_t
memcompose(uint8_t const *m_bytes, size_t m_length)
{
    uint64_t value = 0;
    while (m_length-- > 0)
    {
        value = value << 8 | *m_bytes++;
    }
    return value;
}

/******************************************************************************
 * Decompose the bytes of a number.
 *
 * @param m_bytes Array to store the bytes of the number in, in big-endian
 *     order. (It must have sufficient space for `m_length` elements.)
 * @param m_length Number of bytes to process. At most 8.
 * @param value Number to be decomposed.
 *
 * @return Number of bytes processed (`m_length`).
 *****************************************************************************/
size_t
memdecompose(uint8_t *m_bytes, size_t m_length, uint64_t value)
{
    for (size_t i = m_length; i > 0; --i)
    {
        m_bytes[i - 1] = value;
        value >>= 8;
    }
    return m_length;
}
