/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Password verification
*
* Functions to verify that the password we discover is correct
*
* The password encryption scheme they use is actually terrible for all its complexity
* For a detailed overview of the algorithm and a known-plaintext attack, see
* https://github.com/charlesnathansmith/pwcrack
*
********************************************************************************/

#include <cstdint>
#include "password.h"

// Rotate right
uint32_t ror32(uint32_t value, uint8_t amount)
{
    return (value >> amount) | (value << (32 - amount));
}

// Rotate left
uint32_t rol32(uint32_t value, uint8_t amount)
{
    return (value << amount) | (value >> (32 - amount));
}

// Pasword encryption helper
// I don't know what codex is supposed to mean
// Oreans labeled this function "CodeX1" in their keygen binary's metadata
// It just generates shift registers from an alphanumeric key
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

// Password decrypt a single 32-bit value
uint32_t pw_encrypt(uint32_t in, const char* key)
{
    // Initialize shift registers
    uint32_t shift_a = 0x41363233 ^ key[0];
    shift_a = codex(key, shift_a);

    shift_a ^= ((uint32_t)key[0]) << 8;
    shift_a = codex(key, shift_a);

    return in ^ shift_a;
}

