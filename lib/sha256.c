#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "extras.h"
#include "sha.h"

#define ROTR32(x, n) ((x) >> (n) | (x) << (32 - (n)))

// Hash initialiser.
static uint32_t const
sha256_init[8] =
{
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};

// Round constants.
static uint32_t const
sha256_rc[64] =
{
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U, 0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U, 0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU, 0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U, 0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U, 0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U, 0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U, 0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U, 0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U,
};

// Hash output.
static uint8_t
sha256_bytes[32];

/******************************************************************************
 * Calculate the hash of the given data.
 *
 * @param m_bytes_ Array of bytes representing the big-endian data to hash.
 * @param m_length_ Number of bytes to process. At most 2305843009213693951.
 * @param h_bytes Array to store the bytes of the hash in, in big-endian order.
 *     (It must have sufficient space for 32 elements.) If `NULL`, the hash
 *     will be stored in a static array.
 *
 * @return Array of bytes representing the big-endian hash of the data.
 *****************************************************************************/
uint8_t *
sha256(uint8_t const *m_bytes_, size_t m_length_, uint8_t *h_bytes)
{
    // Initialise the hash.
    uint32_t h_words[8];
    memcpy(h_words, sha256_init, sizeof sha256_init);

    // Create a padded copy whose width in bits is a multiple of 512. Note that
    // the amount of zero-padding required is odd, hence a non-zero number.
    uint64_t nbits = (uint64_t)m_length_ << 3;
    size_t zeros = 512 - ((nbits + 65) & 511U);
    size_t m_length = m_length_ + ((1 + zeros) >> 3) + 8;
    uint8_t *m_bytes = calloc(m_length, sizeof *m_bytes);
    memcpy(m_bytes, m_bytes_, m_length_ * sizeof *m_bytes_);
    m_bytes[m_length_] = 0x80U;
    memdecompose(m_bytes + m_length - 8, 8, nbits);

    // Process each 512-bit chunk.
    uint8_t *m_iter = m_bytes;
    uint32_t schedule[64];
    uint32_t curr[8];
    for(size_t i = 0; i < m_length; i += 64)
    {
        // Expand to 2048 bits.
        for(int j = 0; j < 16; ++j)
        {
            schedule[j] = memcompose(m_iter, 4);
            m_iter += 4;
        }
        for(int j = 16; j < 64; ++j)
        {
            uint32_t sigma0 = ROTR32(schedule[j - 15], 7) ^ ROTR32(schedule[j - 15], 18) ^ schedule[j - 15] >> 3;
            uint32_t sigma1 = ROTR32(schedule[j - 2], 17) ^ ROTR32(schedule[j - 2], 19) ^ schedule[j - 2] >> 10;
            schedule[j] = schedule[j - 16] + schedule[j - 7] + sigma0 + sigma1;
        }

        // Compress to 256 bits.
        memcpy(curr, h_words, sizeof curr);
        for(int j = 0; j < 64; ++j)
        {
            uint32_t Sigma0 = ROTR32(curr[0], 2) ^ ROTR32(curr[0], 13) ^ ROTR32(curr[0], 22);
            uint32_t Sigma1 = ROTR32(curr[4], 6) ^ ROTR32(curr[4], 11) ^ ROTR32(curr[4], 25);
            uint32_t choice = (curr[4] & curr[5]) ^ (~curr[4] & curr[6]);
            uint32_t major = (curr[0] & curr[1]) ^ (curr[1] & curr[2]) ^ (curr[2] & curr[0]);
            uint32_t tmp = curr[7] + Sigma1 + choice + sha256_rc[j] + schedule[j];
            curr[7] = curr[6];
            curr[6] = curr[5];
            curr[5] = curr[4];
            curr[4] = curr[3] + tmp;
            curr[3] = curr[2];
            curr[2] = curr[1];
            curr[1] = curr[0];
            curr[0] = tmp + Sigma0 + major;
        }

        // Calculate the intermediate hash.
        for(int j = 0; j < 8; ++j)
        {
            h_words[j] += curr[j];
        }
    }
    memclear(m_bytes, m_length * sizeof *m_bytes);
    free(m_bytes);

    // Copy the hash to the output array.
    h_bytes = h_bytes == NULL ? sha256_bytes : h_bytes;
    uint8_t *h_iter = h_bytes;
    for(int i = 0; i < 8; ++i)
    {
        h_iter += memdecompose(h_iter, 4, h_words[i]);
    }
    return h_bytes;
}
