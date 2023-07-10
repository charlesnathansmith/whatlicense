/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*   RSA key management
*
* Manages public RSA keys that need to be hotswapped in during analysis
* WL uses libtomcrypt for RSA decryption and signature verification,
* which uses mp_int from libtommath for large integer types,
* so we need to use it too
*
* See
* https://github.com/libtom/libtomcrypt
* https://github.com/libtom/libtommath
*
********************************************************************************/

#pragma once
#include <cstdint>

typedef unsigned long mp_digit;

struct mp_int
{
    int used, alloc, sign;
    mp_digit* dp;
};

class rsa_public_key
{
    mp_int _mod, _exp;

public:
    rsa_public_key() noexcept : _mod{ 0 }, _exp{ 0 } {}

    // Initialize from existing mp_int
    rsa_public_key(const mp_int* mod, const mp_int* exp) { set_from_mpints(mod, exp); }

    // Initialize with byte stream from dummykey.nfo
    rsa_public_key(const uint8_t* mod_bytes, int mod_used, const uint8_t* exp_bytes, int exp_used)
        { set_from_bytes(mod_bytes, mod_used, exp_bytes, exp_used); }

    // Copy constructor
    rsa_public_key(const rsa_public_key& other) { set_from_mpints(&other._mod, &other._exp); }

    // Move constructor
    rsa_public_key(rsa_public_key&& other) noexcept : _mod(other._mod), _exp(other._exp)
        { other._mod.dp = 0; other._exp.dp = 0; }

    // Assignment
    rsa_public_key& operator=(const rsa_public_key& other);

    // Move assignment
    rsa_public_key& operator=(rsa_public_key&& other);

    ~rsa_public_key() noexcept { clear(); }

    bool set_from_mpints(const mp_int* mod, const mp_int* exp);
    bool set_from_bytes(const uint8_t* mod_bytes, int mod_used, const uint8_t* exp_bytes, int exp_used);

    void clear() noexcept;

    const mp_int* n() const noexcept { return (_mod.used) ? &_mod : 0; }
    const mp_int* exp() const noexcept { return (_exp.used) ? &_exp : 0; }
};
