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

#include <cstdint>
#include "tea.h"

// Calculates and stores (key2 ^ a) + key3
void tea_half_round::calc_diff_term()
{
    // Don't recalculate unnecessarily
    if (!diff_term_set)
    {
        // (key2 ^ a) + key3 = b - b_prime - (a << 4) - ((a >> 5) ^ sum)
        diff_term = b - b_prime - (a << 4) - ((a >> 5) ^ sum);
        diff_term_set = true;
    }
}

// Calculates key3 given key2 using the data from this round
uint32_t tea_half_round::key3_from_key2(uint32_t key2)
{
    calc_diff_term();

    //key3 = (key2 ^ a) + key3 - (key2 ^ a)
    return diff_term - (key2 ^ a);
}

// Verifies a key pair
bool tea_half_round::verify_keys(uint32_t key2, uint32_t key3)
{
    uint32_t trial_b_prime = b - ((a << 4) + (key2 ^ a) + ((a >> 5) ^ sum) + key3);

    if (trial_b_prime == b_prime)
        return true;

    return false;
}

// Bitmapping
bitmap::bitmap(tea_intermed& in)
{
    ones_mask = zeros_mask = 0;

    // Fill in needed iterators into input data
    // For each bit position, we need one data entry with an 'a' that has a 1 in that position
    // and one entry with an 'a' that has a 0 in that position in order to solve key2
    for (auto it = in.begin(); it != in.end(); it++)
    {
        uint32_t a = it->a;

        for (size_t bit = 0; bit < 31; bit++)
        {
            if (a & 1)
            {
                if (!((ones_mask >> bit) & 1))  // No iter saved for this place yet
                {
                    // Save the iterator, mark as saved
                    input_iters[bit].one = it;
                    ones_mask |= ((uint32_t)1 << bit);

                    //Calculate differential term we'll need for solving
                    it->calc_diff_term();
                }
            }
            else
            {
                if (!((zeros_mask >> bit) & 1))  // No iter saved for this place yet
                {
                    // Save the iterator, mark as saved
                    input_iters[bit].zero = it;
                    zeros_mask |= ((uint32_t)1 << bit);

                    //Calculate differential term we'll need for solving key2
                    it->calc_diff_term();
                }
            }

            a >>= 1;
        }

        if ((ones_mask & zeros_mask) == 0x7fffffff) // Found all values needed to recover max bits
            break;
    }
}

// Solves for the keys used to produce a vector of half-round data
bool tea_solver(tea_intermed& data, uint32_t* key)
{
    bitmap solver_map(data);

    // Fast solvability info
    uint32_t solvable_bits = solver_map.solvable_bits();

    uint32_t key2 = 0;

    for (size_t bit = 0; bit < 31; bit++)
    {
        if ((solvable_bits >> bit) & 1) // This bit of the key is solvable at this stage
        {
            // Iters must be valid if this bit is solvable
            auto zero_it = solver_map[bit].zero;
            auto  one_it = solver_map[bit].one;

            // Likewise, the diff_terms must have been calculated when data entries were added to bitmap
            // c = (key2 ^ a0) - (key2 ^ a1) + (key3 - key3)
            // c = (key2 ^ a0) - (key2 ^ a1)
            uint32_t c = zero_it->diff_term - one_it->diff_term;

            // For an individual bit n, where n=0 is LSB
            //  c[n+1] =   a0[n+1] ^ a1[n+1] ^ ~key[n] // Binary subtraction
            // ~key[n] =   a0[n+1] ^ a1[n+1] ^ c[n+1]
            //  key[n] = ~(a0[n+1] ^ a1[n+1] ^ c[n+1])
            uint32_t a0_np1 = (zero_it->a >> (bit + 1)) & 1;   // a0[n+1]
            uint32_t a1_np1 = (one_it->a >> (bit + 1)) & 1;    // a1[n+1]
            uint32_t c_np1 = (c >> (bit + 1)) & 1;             //  c[n+1]

            uint32_t k2_n = ~(a0_np1 ^ a1_np1 ^ c_np1) & 1;    // key[n]

            key2 |= k2_n << bit;    // Drop it into the key at the correct position
        }
    }

    // Try all potential key2 values given known good bits
    // 
    // Credit to MBo for solving the key permutation problem before I ever knew I had it:
    // https://stackoverflow.com/questions/49429896/generate-permutations-with-k-fixed-bits
    // There's one more solution where submask==0 that his algorithm misses, though, so we have to add that in

    uint32_t unknown_mask = ~solvable_bits;      // Mask that's 1 for bits we need to solve, 0 for known
    uint32_t known_bits = key2 & solvable_bits;  // Values of only the known good bits with unknowns masked out
    uint32_t key3;
    bool verified = false;

    // Generate possible keys sequentially and verify them against input data
    for (uint32_t submask = unknown_mask; submask != 0; submask = (submask - 1) & unknown_mask)
    {
        key2 = submask | known_bits;
        key3 = data[0].key3_from_key2(key2);

        verified = true;
        size_t count = 0;

        for (auto& in : data)
        {
            if (in.key3_from_key2(key2) != key3)
            {
                verified = false;
                break;
            }
        }

        if (verified)
        {
            key[0] = key2;
            key[1] = key3;
            return true;
        }
    }

    // Test case where submask == 0 if necessary
    if (!verified)
    {
        key2 = known_bits;
        key3 = data[0].key3_from_key2(key2);

        verified = true;
        size_t count = 0;

        for (auto& in : data)
        {
            if (in.key3_from_key2(key2) != key3)
            {
                verified = false;
                break;
            }
        }

        if (verified)
        {
            key[0] = key2;
            key[1] = key3;
            return true;
        }
    }

    return verified;
}

// Perform rounds of TEA encryption on a 64-bit value
void tea_encrypt(uint32_t* buf, uint32_t* key, size_t rounds)
{
    uint32_t sum = 0, a = buf[0], b = buf[1];

    for (size_t i = rounds; i != 0; i--)
    {
        sum += 0x9e3779b9;

        a += (b << 4) + (key[0] ^ b) + ((b >> 5) ^ sum) + key[1];
        b += (a << 4) + (key[2] ^ a) + ((a >> 5) ^ sum) + key[3];
    }

    buf[0] = a, buf[1] = b;
}

// Perform rounds of TEA decryption on a 64-bit value
void tea_decrypt(uint32_t* buf, uint32_t* key, size_t rounds)
{
    uint32_t a = buf[0], b = buf[1];
    uint32_t sum = 0x9e3779b9 * rounds;

    for (size_t i = rounds; i != 0; i--)
    {
        b -= ((a << 4) + (key[2] ^ a) + ((a >> 5) ^ sum) + key[3]);
        a -= ((b << 4) + (key[0] ^ b) + ((b >> 5) ^ sum) + key[1]);

        sum -= 0x9e3779b9;
    }

    buf[0] = a, buf[1] = b;
}