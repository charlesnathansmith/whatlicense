#pragma once
/*********************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
* 
* Bare-bones RSA implementation to handle license signing and encryption
* 
* Don't reuse this for any kind of secure application
* We just need it to format our fake license files correctly
* 
* libtomcrypt would've been the obvious choice, but we don't need 95% of it
* and it's a mess to include.  This does what we need.
* 
 *********************************************/

#include <cstdint>
#include "rsa_key.h"

constexpr unsigned int CRYPT_OK = 0;

// Computes SHA-1 digest
void sha1(uint8_t* const in, size_t in_size, uint8_t* out);

// Generate SHA-1 message for RSA signing
bool rsa_sha1_msg(uint8_t* const in, size_t in_size, size_t mod_size, uint8_t* out);

// RSA encrypt block of up to modulus size
bool rsa_exptmod(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t* out_size);

// RSA sign a message using SHA-1
bool rsa_sign(uint8_t* const in, size_t in_size, rsa_private_key& key, uint8_t* out, size_t out_size);
