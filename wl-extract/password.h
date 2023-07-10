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

#pragma once
#include <cstdint>

// Password decrypt a single 32-bit value
uint32_t pw_encrypt(uint32_t in, const char* key);
