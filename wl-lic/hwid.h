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

#pragma once
#include <cstdint>

#pragma pack(push, 1)

// Structs to simplify accessing parts of ascii HWID as numbers
// Assuming little-endian hardware
struct hwid_bin_term
{
	uint8_t dash;
	uint32_t num;
};

struct hwid_bin
{
	uint16_t		first[2];	// First term
	hwid_bin_term	sec[7];		// Remaining terms
};

// HWID hash
struct hwid_hash
{
	uint8_t		hash_1;
	uint16_t	hash_2[4];
};

#pragma pack(pop)

// Generate HWID hash
void hw_hash(hwid_hash& hash, const char* ascii, uint32_t hwid_key);
