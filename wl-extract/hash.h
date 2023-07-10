/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  Hash extraction tool
*   Main hash
*
*  Main hash structures and related functions
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <string>

// Extracted main hash keys
struct main_hash
{
    uint32_t hash_1, hash_2;    // Hashes calculated from main_hash
    uint16_t hash_3;
    uint32_t tea_key[4];        // TEA encryption key
    std::string password;       // Password encryption key
    uint32_t hwid_key;          // HWID key
};

// Main hash binary format
// These are just references into parts of the final alphanumeric main_hash
#pragma pack(push,1)
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
    char null_term;             // Not part of actual hash, used here to null terminate the string output

    main_hash_bin() : null_term(0) {}
    char* c_str() { return (char*) &unused_1[0]; }
};
#pragma pack(pop)

// Finds two alphanumeric strings a and b that could sum together to a given value
// Returns false if invalid input provided (individual sum bytes should be between 0x60 and 0xf4)
bool solve_alphanum_sum(uint8_t* a, uint8_t* b, const uint8_t* sum, size_t size);

// solve_alphanum_sum for 32-bit sum
bool solve_alphanum_sum32(uint32_t* a, uint32_t* b, uint32_t sum);

// solve_alphanum_sum for 16-bit sum
bool solve_alphanum_sum16(uint16_t* a, uint16_t* b, uint16_t sum);
