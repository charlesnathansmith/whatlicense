/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*   Miscellaneous Utilities
*
********************************************************************************/

#pragma once
#include <string>
#include "pin.H"

// Get reference to data at address x
#define rbyte(x)  *((uint8_t*) (x))
#define rword(x)  *((uint16_t*)(x))
#define rdword(x) *((uint32_t*)(x))

// Find potential HWID in a string
bool find_hwid(const char* text, char* out);

// Returns true if str ends with substr
bool string_endswith(const std::string& str, const std::string& substr);
