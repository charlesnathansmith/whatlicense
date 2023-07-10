/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-lic
*  License generation tool
*   Encryption types and functions
*
********************************************************************************/

#include <cstdint>
#include "utils.h"
#include "lictypes.h"
#include "crypt.h"

// Generate arbitrary main_hash keys (for dummy license)
void main_hash_key::randomize()
{
    // These just have to be something remotely valid here
    hash_3 = hash_1 = hash_2 = hwid_key = rnd();
    for (auto& k : tea_key) k = rnd();
    
    // The password is different for every protected file and we just need a stand-in value here
    // For some unknown reason it can't be completely random or verification fails before the RSA sig check
    // This is the simplest known-good value I could find that will work properly during extraction
    password = "11111111111111111111111111111111";

    valid = true;
}

// Extract main_hash keys from a supplied main_hash string
bool main_hash_key::extract(const char* ascii)
{
    if (strlen(ascii) < sizeof(main_hash_bin))
        return false;

    main_hash_bin *m = (main_hash_bin*) ascii;

    hash_1 = m->hash_1_[0] + m->hash_1_[1];
    hash_2 = m->hash_2_[0] + m->hash_2_[1];
    hash_3 = m->hash_3_[0] + m->hash_3_[1];

    for (size_t i = 0; i < 4; i++)
        tea_key[i] = m->tea_key_1_[i] + m->tea_key_2_[i];

    password.assign(m->password, 32);

    hwid_key = m->hwid_key;

    valid = true;
}

// Basic xor_add encoding for license core
void core_encode(uint8_t* buf, size_t size, uint16_t key)
{
    uint8_t key_hi = key >> 8;
    uint8_t key_lo = key & 0xFF;

    for (size_t i = 0; i < size; i++)
        buf[i] = (buf[i] ^ key_lo) + key_hi;
}

// TEA encyption
void tea_encrypt(uint32_t* buf, size_t size, uint32_t* key)
{
    size_t num_blocks = size / 8;

    for (size_t cur_block = 0; cur_block < num_blocks; cur_block++)
    {
        uint32_t* b = &buf[cur_block * 2];
        uint32_t sum = 0;

        for (size_t i = 0; i < 32; i++)
        {
            sum += 0x9e3779b9;  //delta
            b[0] += (b[1] << 4) + (b[1] ^ key[0]) + ((b[1] >> 5) ^ sum) + key[1];
            b[1] += (b[0] << 4) + (b[0] ^ key[2]) + ((b[0] >> 5) ^ sum) + key[3];
        }
    }
}

// Pasword encryption helper
uint32_t codex(const char* key, uint32_t shift)
{
    uint16_t counter = 0;

    do {
        shift ^= ((uint32_t)*key) << 8;

        do {
            shift = (shift ^ (counter & 0xFF)) + 0x7034616b;
            shift = ror32(shift, shift & 0xFF);
            shift ^= 0x8372a5a7;
            counter--;
        } while (counter != 0);
    } while (*key++ != 0);

    return shift;
}

// Password encryption
void pw_encrypt(uint32_t* buf, size_t size, const char* key)
{
    size_t num_blocks = size / 4;

    // Initialize shift registers
    uint32_t shift_a = 0x41363233 ^ key[0];
    uint32_t shift_b = shift_a = codex(key, shift_a);

    shift_a ^= ((uint32_t)key[0]) << 8; //Better safe than sorry with the type promote
    shift_a = codex(key, shift_a);

    // Encryption loop
    for (size_t i = 0; i < num_blocks; i++)
    {
        buf[i] ^= shift_a;

        shift_b = rol32(shift_b, shift_a & 0xff);
        shift_a ^= shift_b;

        shift_a = ror32(shift_a, (shift_b >> 8) & 0xff);
        shift_b += shift_a;
    }
}

// String and tail encryption
void str_tail_encrypt(uint8_t* buf)
{
    // Uses the first dword of the license buffer as a key
    uint32_t shift = pdword(buf);
    
    // Start at the beginning of the strings section
    uint8_t* pos = buf + sizeof(license_head);

    // Encrypt up to last license_tail end markers
    while (!((pdword(pos) == 0xfffffffe) && (pdword(pos + 4) == 0xfffffffe)))
    {
        *pos ^= shift;
        *pos += (shift >> 8);
        shift = ror32(shift, 1);
        pos++;
    }
}

// Final checksum on main license body
// Putting this here since it's a one-off and not really a utility
size_t final_checksum(uint8_t* buf)
{
    uint8_t sum[4] = { 0 };
    size_t state = 0;
    uint8_t* pos = buf;

    while (!((pdword(pos) == 0xfffffffe) && (pdword(pos + 4) == 0xfffffffe)))
    {
        size_t i = state % 4;

        switch (i)
        {
        case 0:
        case 1:
            sum[i] += *pos;
            break;
        case 2:
        case 3:
            sum[i] ^= *pos;
            break;
        }
        pos++;
        state++;
    }

    // pos = &tail.checksum;
    pos += 8;

    // Write checksum;
    pdword(pos) = (sum[1] << 24) | (sum[0] << 16) | (sum[3] << 8) | sum[2];

    // Return total buffer size (one past end of checksum) - (start of license)
    return (pos + 4) - buf;
}
