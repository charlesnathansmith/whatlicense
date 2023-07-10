/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-lic
*  License generation tool
*   General WL license building functions
*
********************************************************************************/

#pragma once
#include <cstdint>
#include "rsa/rsa.h"
#include "utils.h"
#include "lictypes.h"
#include "hwid.h"
#include "crypt.h"

// String section size
size_t lic_str_size(reg_info& reg);

// Main license body size
size_t lic_main_size(reg_info& reg);

// Build core layer
void lic_build_core(lic_core& core, main_hash_key& m, reg_info& reg);

// Build TEA layer
void lic_build_tea(lic_tea& tea, reg_info& reg);

// Encrypt lower layers and finish license_head
void lic_finish_head(license_head& head, main_hash_key& m, reg_info& reg);

// Write strings section of the license
size_t lic_write_strs(uint8_t* dst, size_t dst_size, reg_info& reg);

// Build license tail section and perform final encryption and checksum
// Needs pointer to beginning of the entire license buffer and a tail pointer
void lic_build_tail(uint8_t* lic_buf, license_tail& tail);

// Calculate size of final encrypted license buffer
size_t lic_final_size(size_t signed_size, rsa_private_key& pk);

// RSA encrypt in blocks to produce final license
size_t lic_rsa_encrypt(uint8_t* in, size_t in_size, rsa_private_key& pk, uint8_t* out, size_t out_size);