/****************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   License detail management
*
* Manages information about the license file we're using
*
********************************************************************************/

#include <iostream>
#include <cstdint>
#include <string>
#include "pin.H"
#include "rsakey.h"
#include "licdetails.h"

// RSA file header
// The are just the lengths in mp_digits of each value, which are then stored
// immaediatley after as a run of dwords
#pragma pack(push, 1)
struct rsa_head
{
	uint8_t mod1_len, exp1_len, mod2_len, exp2_len;
};
#pragma pack(pop)

// Load license and RSA file data
int lic_details::load(const std::string& lic_path, const std::string& key_path)
{
	char abs_path[_POSIX_PATH_MAX];

	// Get absolute path to license file
	OS_RETURN_CODE ret = OS_Realpath(lic_path.c_str(), true, abs_path);

	if (ret.generic_err != OS_RETURN_CODE_NO_ERROR)
		return LD_ERROR_BAD_LICENSE;

	// Store NT path
	nt_path = "\\??\\";
	nt_path += abs_path;

	// Read first 8 bytes of key file to compare to files mapped to memory
	std::ifstream lic_file(lic_path, std::ios::binary);
	head.resize(8);

	if (!lic_file.read(&head[0], 8))
		return LD_ERROR_BAD_LICENSE;

	// Get key file size
	lic_file.seekg(0, std::ios::end);
	size = lic_file.tellg();

	lic_file.close();

	// Import RSA public keys
	rsa_head inf;
	std::ifstream inf_file(key_path, std::ios::binary);

	// Try to read RSA file header
	if (!inf_file.read((char*)&inf, sizeof(inf)))
		return LD_ERROR_BAD_RSA;

	// None of these sizes should be zero
	if (!inf.mod1_len || !inf.exp1_len || !inf.mod2_len || !inf.exp2_len)
		return LD_ERROR_BAD_RSA;

	// Read RSA public key data
	std::string mod1, exp1, mod2, exp2;
	mod1.resize(inf.mod1_len * sizeof(mp_digit));
	exp1.resize(inf.exp1_len * sizeof(mp_digit));
	mod2.resize(inf.mod2_len * sizeof(mp_digit));
	exp2.resize(inf.exp2_len * sizeof(mp_digit));

	if (!inf_file.read(&mod1[0], inf.mod1_len * sizeof(mp_digit)) ||
		!inf_file.read(&exp1[0], inf.exp1_len * sizeof(mp_digit)) ||
		!inf_file.read(&mod2[0], inf.mod2_len * sizeof(mp_digit)) ||
		!inf_file.read(&exp2[0], inf.exp2_len * sizeof(mp_digit)))
		return LD_ERROR_BAD_RSA;

	// Set RSA public keys from data
	if (!rsa_key_1.set_from_bytes((uint8_t*)mod1.c_str(), inf.mod1_len, (uint8_t*)exp1.c_str(), inf.exp1_len) ||
		!rsa_key_2.set_from_bytes((uint8_t*)mod2.c_str(), inf.mod2_len, (uint8_t*)exp2.c_str(), inf.exp2_len))
		return LD_ERROR_BAD_RSA;

	return 0;
}
