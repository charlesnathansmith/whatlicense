/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   TEA key solver
*
* Solves key for TEA variant used in the protection scheme
* See https://github.com/charlesnathansmith/teasolver for solving details
*
* Nomenclature is based around solving the (key2, key3) half-rounds,
* but the same calculations are reused to solve the (key0, key1) half-rounds
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <vector>

// Data collected about a single TEA half-round of the form
// b -= ((a << 4) + (key2 ^ a) + ((a >> 5) ^ sum) + key3);
struct tea_half_round
{
    uint32_t a, b, sum, b_prime;
    uint32_t diff_term;
    bool diff_term_set;

    tea_half_round(uint32_t sum) :
        a(0), b(0), sum(sum), b_prime(0), diff_term(0), diff_term_set(false) {}

    // Calculates and stores differential value (key2 ^ a) + key3
    void calc_diff_term();

    // Calculates key3 given key2 using the data from this round
    uint32_t key3_from_key2(uint32_t key2);

    // Verifies a key pair
    bool verify_keys(uint32_t key2, uint32_t key3);
};

// Vector of half-round data needed to solve one key pair
typedef std::vector<tea_half_round> tea_intermed;

// Solves for the keys used to produce a vector of half-round data
bool tea_solver(tea_intermed& data, uint32_t* key);

// Perform rounds of TEA encryption on a 64-bit value
void tea_encrypt(uint32_t* buf, uint32_t* key, size_t rounds);

// Perform rounds of TEA decryption on a 64-bit value
void tea_decrypt(uint32_t* buf, uint32_t* key, size_t rounds);

// Bitmapping
// For each key bit we want to solve, we need to find pairs of round data with 'a' values that differ at that bit
struct bit_info
{
    tea_intermed::iterator one, zero;
};

class bitmap
{
    bit_info input_iters[31];       // Holds iterators to round data entries that have 1s or 0s in the necessary bit positions
    uint32_t ones_mask, zeros_mask; // Keeps up with whether we've found valid round data entries for each of the bits

public:
    bitmap(tea_intermed& in);

    // Bit mask indicating bits recoverable by fast solver
    uint32_t solvable_bits() const { return ones_mask & zeros_mask; }

    // Access to discovered input entries needed for solving
    // Caller responsible for requesting an in-bounds element with corresponding solvable bit set
    // If you ask for garbage, garbage you shall receive
    const bit_info& operator[](size_t i) const { return input_iters[i]; }
};