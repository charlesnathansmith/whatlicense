/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-lic
*  License generation tool
*   Hardware ID (HWID) types and functions
*
********************************************************************************/

#include <cstdint>
#include "hwid.h"

// Converts '1' to 0x01, 'A' to 0x0A, etc
uint8_t ascii_to_nib(uint8_t ascii)
{
    if (ascii >= '0' && ascii <= '9')
        return ascii - '0';
    else if (ascii >= 'A' && ascii <= 'F')
        return ascii - 0x37;
    else if (ascii >= 'a' && ascii <= 'f')
        return ascii - 0x57;
    else return 0;
}

// Converts "1A" to 0x1A, etc.
uint8_t ascii_to_byte(uint16_t ascii)
{
    return ascii_to_nib(ascii >> 8) + (ascii_to_nib(ascii & 0xFF) << 4);
}

// Converts "AB12" to 0xAB12, etc (little endian, so "\x12\xAB")
uint16_t ascii_to_word(uint32_t ascii)
{
    return  ascii_to_byte(ascii >> 16) + (ascii_to_byte(ascii & 0xffff) << 8);
}

// Generate HWID hash
void hw_hash(hwid_hash& hash, const char* ascii, uint32_t hwid_key)
{
    // Treat ascii HWID as binary structure
    // Assumes little-endian hardware
    hwid_bin* bin = (hwid_bin*) ascii;

    // Compute HWID hash values
    hash.hash_1 = ascii_to_byte(bin->first[0]) + ascii_to_byte(bin->first[1]);
    hash.hash_2[0] = ascii_to_word(bin->sec[0].num) + ascii_to_word(bin->sec[1].num);
    hash.hash_2[1] = ascii_to_word(bin->sec[2].num) + ascii_to_word(bin->sec[3].num);
    hash.hash_2[2] = ascii_to_word(bin->sec[4].num) + ascii_to_word(bin->sec[5].num);

    hash.hash_2[3] = hash.hash_1 ^ hash.hash_2[0] ^ hash.hash_2[1] ^ hash.hash_2[2] ^ hwid_key;
}
