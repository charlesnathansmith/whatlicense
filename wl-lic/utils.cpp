/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-lic
*  License generation tool
*   Miscellaneous utilities
*
********************************************************************************/

#define _CRT_SECURE_NO_WARNINGS

#include <cstdint>
#include <string.h>
#include "utils.h"

// Random enough for our purposes
uint32_t rnd() { return 0xaabbccdd; }

// String checksum
uint16_t str_checksum(const char* str)
{
    uint16_t sum_high = 0, sum_low = 0;

    if (!str)
        return 0;

    for (size_t i = 0; str[i] != '\0'; i++)
        if (i % 2)
            sum_low ^= str[i];
        else
            sum_high += str[i];

    return (sum_high << 8) | (sum_low & 0xff);
}

// Binary checksum
uint16_t bin_checksum(const uint8_t* buf, size_t size)
{
    size_t sum_high = 0, sum_low = 0;

    for (size_t i = 0; i < size; i++)
        if (i % 2)
            sum_low += buf[i];
        else
            sum_high ^= buf[i];

    return (uint16_t)((sum_high << 8) | (sum_low & 0xFF));
}

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

// Writes license strings in correct format, including end markers
int WriteLicString(uint8_t* pos, const char* str, size_t out_size)
{
    // Check for valid string pointer
    size_t str_len = (str) ? strlen(str) + 1 : 0;
    size_t total_len = str_len + 8;

    // Return if not enough room
    if (((int)out_size - total_len) < 0)
        return 0;

    // Copy string to buffer including null if it exists
    if (str)
    {
        strncpy((char*)pos, str, str_len + 1);
        pos += str_len;
    }

    // Copy end of string marker into buffer
    pdword(pos) = 0x0FFFFFFF;
    pdword(pos + 4) = 0x0FFFFFFF;

    return total_len;
}
