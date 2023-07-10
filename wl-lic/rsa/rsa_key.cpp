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
#include <memory>
#include <string>
#include "libtommath/tommath.h"
#include "rsa_key.h"

// Base36 decode ASCII char to half byte
uint8_t base36_decode_nib(uint8_t in)
{
	if ((in < '0') || (in > '9'))
		in -= 0x57;
	else
		in -= 0x30;

	return in;
}

// Base36 decode an ASCII string
bool base36_decode(const char* in, uint8_t* out, size_t out_size)
{
	if (!in || !out)
		return false;

	for (size_t i = 0; i < out_size; i++)
	{
		if (!in[0] || !in[1])
			return false;

		out[i] = (base36_decode_nib(in[0]) << 4) | base36_decode_nib(in[1]);
		in += 2;
	}

	return true;
}

// Read big-endian number represented by up to 4 bytes
// Needed to read DER value length field
uint32_t read_big_endian32(uint8_t* bytes, size_t size)
{
	if (size > 4)
		return 0;

	uint32_t num = 0;

	while (size--)
	{
		num <<= 8;
		num |= *bytes++;
	}

	return num;
}

// Safely increment a position pointer by amount
// Should probably C++-ify DER integer reading better to avoid the pointer juggling
bool ptr_safe_inc(uint8_t** pos, size_t amount, uint8_t* end)
{
	*pos += amount;

	if (*pos >= end)
		return false;

	return true;
}

// Read an integer from a DER stream
// Returns total size of record in bytes or 0 if error
size_t read_der_int(mp_int* n, uint8_t* der, uint8_t* end)
{
	uint8_t type = *der;

	// Type should be integer
	if (type != 0x02)
		return 0;

	// Safely increment past type byte
	if (!ptr_safe_inc(&der, 1, end))
		return 0;

	// Total record size to return
	size_t rec_size = 2;  // Size of type and len_byte

	// Length of value
	size_t len = 0;
	uint8_t len_byte = *der;

	if (!(len_byte & 0x80))
	{
		// Single-byte length
		len = len_byte;

		// Inc past length byte
		if (!ptr_safe_inc(&der, 1, end))
			return 0;
	}
	else
	{
		// Multi-byte length
		// Length of the bytes representing the length of the value
		uint8_t len_len = len_byte & 0x7f;
		rec_size += len_len;

		// Value length should fit in a 32-bit number (or something went very wrong)
		if (len_len > 4)
			return 0;

		// Inc past length of length byte
		if (!ptr_safe_inc(&der, 1, end))
			return 0;

		// Make sure reading length data won't overflow
		if (der + len_len >= end)
			return 0;

		len = read_big_endian32(der, len_len);

		// Inc past len data
		if (!ptr_safe_inc(&der, len_len, end))
			return 0;
	}

	rec_size += len;

	// Make sure reading value won't overflow
	if (der + len > end)
		return false;

	// Read value data
	mp_from_ubin(n, der, len);

	return rec_size;
}

/********************
*  rsa_key
*********************/

// Copy
rsa_key::rsa_key(const rsa_key& rhs)
{
	mp_init_copy(&_n, &rhs._n);
	mp_init_copy(&_exp, &rhs._exp);
}

// Assignment
rsa_key& rsa_key::operator=(const rsa_key& rhs)
{
	mp_clear_multi(&_n, &_exp, NULL);  // Put in known state
	mp_init_copy(&_n, &rhs._n);
	mp_init_copy(&_exp, &rhs._exp);

	return *this;
}

// Extracts private key from a base-36 encoded, DER encoded ASCII string
bool rsa_key::import_from_base36der(const char* in)
{
	size_t der_size = strlen(in) / 2;
	uint8_t* der = new uint8_t[der_size];

	// Extract the key
	if (!base36_decode(in, der, der_size))
	{
		delete[] der;
		return false;
	}

	if	(!import_from_der(der, der_size))
	{
		delete[] der;
		return false;
	}

	delete[] der;
	return true;
}

/********************
*  rsa_private_key
*********************/

// Extracts private key from a DER encoded packet
bool rsa_private_key::import_from_der(uint8_t* der, size_t size)
{
	// Private key should be version 0 (2-prime)
	if ((size < 3) || memcmp(der, "\x02\x01\x00", 3))
		return false;

	uint8_t* end = der + size;

	// Safely increment buffer past version integer we just verified
	if (!ptr_safe_inc(&der, 3, end))
		return false;

	// Holder for discarded public exponent
	mp_int e;
	mp_init(&e);
	
	// Extract the key integers -- not worrying about CRT optimization for now
	if (!(size = read_der_int(&_n, der, end)) ||	// Read modulus n
		!ptr_safe_inc(&der, size, end))
		return false;

	if (!(size = read_der_int(&e, der, end)) ||			// Read public exponent e (discarded)
		!ptr_safe_inc(&der, size, end))
		return false;

	if (!(size = read_der_int(&_exp, der, end)))		// Read private exponent d
		return false;

	mp_clear(&e);

	return true;
}

/********************
*  rsa_public_key
*********************/

// Extracts public key from a DER encoded packet
bool rsa_public_key::import_from_der(uint8_t* der, size_t size)
{
	uint8_t* end = der + size;

	// Extract the key integers
	if (!(size = read_der_int(&_n, der, end)) ||	// Read modulus n
		!ptr_safe_inc(&der, size, end))
		return false;

	if (!(size = read_der_int(&_exp, der, end)))	// Read public exponent e
		return false;

	return true;
}
