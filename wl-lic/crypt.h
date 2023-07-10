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

#pragma once
#include <cstdint>
#include <string>

// Main hash binary format
struct main_hash_bin
{
    uint32_t unused_1[2];		// Unused

    uint32_t hash_1_[2];		// Added together to get hash_1
    uint32_t hash_2_[2];		// Added together to get hash_2
    uint16_t hash_3_[2];		// Added together to get hash_3
    uint32_t tea_key_1_[4];	    // tea_key[0] = tea_key_1_[0] + tea_key_2_[0]
    uint32_t tea_key_2_[4];	    // etc.

    uint32_t unused_2[2];		// Unused

    char     password[32];      // Used for password encryption
    uint32_t hwid_key;		    // Used for HWID hashing
};

// Extracted main_hash keys
struct main_hash_key
{
    uint32_t hash_1, hash_2;    // Hashes calculated from main_hash
    uint16_t hash_3;
    uint32_t tea_key[4];        // TEA encryption key
    std::string password;       // Password encryption key
    uint32_t hwid_key;          // HWID key

    bool valid;

    main_hash_key() : valid(false), hash_1(0), hash_2(0),
        hash_3(0), tea_key(), hwid_key(0) {}

    // Set main_hash keys to a default value (for dummy license)
    void randomize();

    // Extract main_hash keys from a supplied main_hash string
    bool extract(const char* ascii);
};

// Basic xor_add encoding for license core
void core_encode(uint8_t* buf, size_t size, uint16_t key);

// TEA encyption
void tea_encrypt(uint32_t* buf, size_t size, uint32_t* key);

// Password encryption
void pw_encrypt(uint32_t* buf, size_t size, const char* key);

// String and tail encryption
void str_tail_encrypt(uint8_t* buf);

// Final checksum on main license body
// Putting this here since it's a one-off and not really a utility
size_t final_checksum(uint8_t* buf);
