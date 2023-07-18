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

#include <cstdint>
#include "rsakey.h"

// Assignment
rsa_public_key& rsa_public_key::operator=(const rsa_public_key& other)
{
	if (this != &other) set_from_mpints(&other._mod, &other._exp);
	return *this;
}

// Move assignment
rsa_public_key& rsa_public_key::operator=(rsa_public_key&& other)
{
	if (this != &other)
	{
		clear();
		_mod = other._mod;
		_exp = other._exp;
	}

	return *this;
}

// Clear the mp_int values
void rsa_public_key::clear() noexcept
{
	delete[] _exp.dp;
	delete[] _mod.dp;

	_exp = _mod = { 0 };
}

bool rsa_public_key::set_from_mpints(const mp_int* mod, const mp_int* exp)
{
	clear();

	if (!mod || !exp || !mod->dp || !exp->dp)
		return false;	// Null arguments or digit fields

	_mod.used = _mod.alloc = mod->used;
	_exp.used = _exp.alloc = exp->used;

	_mod.dp = new mp_digit[_mod.used];
	_exp.dp = new mp_digit[_exp.used];

	for (size_t i = 0; i < _mod.used; i++)
		_mod.dp[i] = mod->dp[i];

	for (size_t i = 0; i < _exp.used; i++)
		_exp.dp[i] = exp->dp[i];

	return true;
}

// Sets _mod and _exp from bytetreams retrieved from dummykey.nfo
bool rsa_public_key::set_from_bytes(const uint8_t* mod_bytes, size_t mod_used, const uint8_t* exp_bytes, size_t exp_used)
{
	clear();

	if (!mod_bytes || !exp_bytes)
		return false;

	// Allocate mp_digit buffers
	_mod.dp = new mp_digit[mod_used];
	_exp.dp = new mp_digit[exp_used];

	// Set number of digits for mod and exp
	_mod.used = _mod.alloc = mod_used;
	_exp.used = _exp.alloc = exp_used;

	for (size_t i = 0; i < mod_used; i++)
		_mod.dp[i] = ((mp_digit*)(mod_bytes))[i];

	for (size_t i = 0; i < exp_used; i++)
		_exp.dp[i] = ((mp_digit*)(exp_bytes))[i];
	
	return true;
}
