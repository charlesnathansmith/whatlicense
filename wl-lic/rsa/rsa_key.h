#pragma once
/*********************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
* Bare-bones RSA key management
*
* Don't reuse this for any kind of secure application
* We just need it to format our fake license files correctly
*
* Copy and assignment contructors were added just for good form since mp_int uses dynamic memory
* There is never any need to use those in this project, and again this RSA implementation should
* never be relied upon outside of this project, so those have not been thoroughly tested (fair warning)
*
 *********************************************/

#include <cstdint>
#include "libtommath/tommath.h"

// Base36 decode an ASCII string
bool base36_decode(const char* in, uint8_t* out, size_t out_size);

// Read an integer from a DER stream
size_t read_der_int(mp_int* n, uint8_t* der, uint8_t* end);

// Common base class for public or private RSA key
class rsa_key
{
protected:
	mp_int _n, _exp;				// modulus, exponent

public:
	rsa_key() { mp_init_multi(&_n, &_exp, NULL); }

	// Copy and assignment
	rsa_key(const rsa_key& rhs);
	rsa_key& operator=(const rsa_key& rhs);

	~rsa_key() { mp_clear_multi(&_n, &_exp, NULL); }

	// Extract key from a DER-encoded packet
	virtual bool import_from_der(uint8_t* der, size_t size) = 0;

	// Extracts private key from a base-36 encoded, DER-encoded ASCII string
	bool import_from_base36der(const char* in);

	// Get modulus and private exponents
	const mp_int* n() const { return static_cast<const mp_int*>(&_n); }
	const mp_int* exp() const { return static_cast<const mp_int*>(&_exp); }

	// Get modulus size in bytes
	size_t size() const { return mp_count_bits(&_n) / 8; }
};

class rsa_private_key : public rsa_key
{
public:
	using rsa_key::rsa_key;

	// Extract private key from a DER-encoded packet
	bool import_from_der(uint8_t* der, size_t size) override;
};

class rsa_public_key : public rsa_key
{
public:
	using rsa_key::rsa_key;

	// Extract public key from a DER-encoded packet
	bool import_from_der(uint8_t* der, size_t size) override;
};
