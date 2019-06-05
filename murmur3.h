/**
 * Zero Copy Packet Processing
 * xProbe IPFIX exporter
 *
 * MASTER'S THESIS
 * FIT VUT BRNO 2019
 * @author Bc. Ondrej Ploteny <xplote01@stud.fit.vutbr.cz>
 *
 * @file: murmur3.h
 * @brief This file contains hash function murmur3 of Austin Appleby
 * This source code was taken from ipt_NETFLOW linux 2.6.x-5.x kernel module by <abc@openwall.com> -- 2008-2019.
 * Retrieved from https://github.com/aabc/ipt-netflow/blob/master/murmur3.h
 *
 * created on 3.3.2019
 */


#ifndef HASH_TABLE_MURMUR3_H
#define HASH_TABLE_MURMUR3_H


/* MurmurHash3, based on https://code.google.com/p/smhasher of Austin Appleby. */

static __always_inline uint32_t rotl32(const uint32_t x, const int8_t r)
{
    return (x << r) | (x >> (32 - r));
}

static __always_inline uint32_t fmix32(register uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}
/**
 * @brief Compute hash value from key,
 * source code taken from https://github.com/aabc/ipt-netflow/blob/master/murmur3.h
 * @param[in] ctx Context of hash table
 * @param[in] len Size of flow key data structure
 * @param[in] seed Random number generated when application start
 * @return 32-bit hash value
 */
static inline uint32_t murmur3(const void *key, const uint32_t len, const uint32_t seed)
{
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;
    const uint32_t *blocks;
    const uint8_t *tail;
    register uint32_t h1 = seed;
    uint32_t k1 = 0;
    uint32_t i;

    blocks = (const uint32_t *)key;
    for (i = len / 4; i; --i) {
        h1 ^= rotl32(*blocks++ * c1, 15) * c2;
        h1 = rotl32(h1, 13) * 5 + 0xe6546b64;
    }
    tail = (const uint8_t*)blocks;
    switch (len & 3) {
        case 3: k1 ^= tail[2] << 16;
        case 2: k1 ^= tail[1] << 8;
        case 1: k1 ^= tail[0];
            h1 ^= rotl32(k1 * c1, 15) * c2;
    }
    return fmix32(h1^ len);
}

#endif //HASH_TABLE_MURMUR3_H
