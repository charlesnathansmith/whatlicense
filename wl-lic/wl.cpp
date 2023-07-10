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

// Disable strncpy compalaint
#define _CRT_SECURE_NO_WARNINGS

#include <cstdint>
#include "rsa/rsa.h"
#include "lictypes.h"
#include "utils.h"
#include "hwid.h"
#include "crypt.h"
#include "wl.h"

// String section size
size_t lic_str_size(reg_info& reg)
{
	return ((reg.name.size())    ? (reg.name.size()    + 1) : 0)
		 + ((reg.company.size()) ? (reg.company.size() + 1) : 0)
		 + ((reg.custom.size())  ? (reg.custom.size()  + 1) : 0)
		 + reg.hwid.size()	// hwid doesn't get a terminating null
		 + 8 * 4;			// String delineation markers
}

// Main license body size
size_t lic_main_size(reg_info& reg)
{
    // Fixed
    size_t size = sizeof(license_head) + sizeof(license_tail);

    // Variable
	return size + lic_str_size(reg);
}

// Build core layer
void lic_build_core(lic_core& core, main_hash_key& m, reg_info& reg)
{
	// Hashes computed from main_hash
	core.hash_1 = m.hash_1;
	core.hash_2 = m.hash_2;

	// Hwid hash
	if (reg.hwid.size() >= sizeof(hwid_bin))
		hw_hash(core.hwid_hash, reg.hwid.c_str(), m.hwid_key);

	// Unused license feature details set to random numbers
	core.num_days = rnd();
	core.num_execs = rnd();
	core.exp_date = rnd();
	core.global_minutes = rnd();
	core.country_id = rnd();
	core.runtime = rnd();
}

// Build TEA layer
void lic_build_tea(lic_tea& tea, reg_info& reg)
{
	// Encrypt core
	// If core_xor_key = 0, core is not encrypted
	// tea.core_xor_key = rnd();
	tea.core_xor_key = 0;

	core_encode((uint8_t*) &tea.core, sizeof(lic_core), tea.core_xor_key);

	// Can use the LF_ flags to add license "features" (restrictions)
	// Some protected programs will complain if we don't enforce HWID locking
	tea.lic_flags = LF_HWID;

	tea.random = rnd();

	//Strings checksum
	tea.str_checksum = str_checksum(reg.name.c_str())   + str_checksum(reg.company.c_str())
					 + str_checksum(reg.custom.c_str()) + str_checksum(reg.hwid.c_str());

	// Binary checksum calculated on buffer up to the checksum position
	size_t chksum_size = (size_t )&tea.checksum - (size_t) &tea;
	tea.checksum = bin_checksum((uint8_t*)&tea, chksum_size);

	tea.magic = 0xe2b27878;		// Hardcoded magic number
}

// Encrypt lower layers and finish license_head
void lic_finish_head(license_head& head, main_hash_key& m, reg_info& reg)
{
	// Another hash from main_hash
	head.hash_3 = m.hash_3;

	// Strings checksum (same as we did earlier)
	head.str_checksum = str_checksum(reg.name.c_str()) + str_checksum(reg.company.c_str())
					  + str_checksum(reg.custom.c_str()) + str_checksum(reg.hwid.c_str());

	// Final license head checksum
	size_t chksum_size = (size_t) &head.checksum - (size_t) &head;
	head.checksum = bin_checksum((uint8_t*) &head, chksum_size);
}

// Write strings section of the license
size_t lic_write_strs(uint8_t* dst, size_t dst_size, reg_info& reg)
{
	size_t written = lic_str_size(reg);

	if (dst_size < written)
		return 0;

	// These get null-terminators if present
	for (auto s : { &reg.name, &reg.company, &reg.custom })
	{         
		memset(dst, 0xff, 8);

		if (s->size())
			strncpy((char*)(dst + 8), s->c_str(), s->size() + 1);
		
		dst += 8 + s->size() + 1;
	}

	// hwid does not
	memset(dst, 0xff, 8);

	if (reg.hwid.size())
		strncpy((char*)(dst + 8), reg.hwid.c_str(), reg.hwid.size());

	return written;
}

// Build license tail section and perform final encryption and checksum
// Needs pointer to beginning of the entire license buffer and a tail pointer
void lic_build_tail(uint8_t* lic_buf, license_tail& tail)
{
	// This is all boilerplate since we aren't enforcing anything
	tail.double_null = 0;
	tail.beg_marker[0] = tail.beg_marker[1] = 0xfffffffd;
	tail.magic[0] = 0x83a9b0f1;
	tail.magic[1] = 0x1c;
	tail.random = rnd();

	tail.install_by = tail.net_instances = 0;			// Not enforcing these
	tail.creation_date = (2023 << 16) | (1 << 8) | 2;	// Jan 2, 2023 -- Just has to be sensible
	tail.unknown = 0;									// Probably used by SmartActivate licenses

	tail.end_marker[0] = tail.end_marker[1] = 0xfffffffd;
	tail.end_marker[2] = tail.end_marker[3] = 0xfffffffe;

	// String and tail encryption
	str_tail_encrypt((uint8_t*) lic_buf);

	// Final main body checksum
	final_checksum((uint8_t*) lic_buf);
};

size_t lic_final_size(size_t signed_size, rsa_private_key& pk)
{
	// Encryption loop reads in blocks of 0x7f, spits out blocks of pk.size()
	size_t fin_size = (signed_size / 0x7f) * pk.size();

	// Any remaining bytes in the signed license are just copied over to final license
	return fin_size + (signed_size % 0x7f);
}

// RSA encrypt in blocks to produce final license
size_t lic_rsa_encrypt(uint8_t* in, size_t in_size, rsa_private_key& pk, uint8_t* out, size_t out_size)
{
	if (out_size < lic_final_size(in_size, pk))
		return 0;

	// RSA encrypt with private_key_2
	uint8_t* out_pos = out;
	size_t written;

	size_t i = 0;
	for (; i + 0x7f < in_size; i += 0x7f)
	{
		written = 0xfe;

		if (!rsa_exptmod(in + i, 0x7f, pk, out_pos, &written))
			return false;

		// Blocks of size 0x7f are read, but are encrypted to pk.size() length blocks (generally 0x80)
		out_pos += written;
	}

	// Copy over remaining license bytes that couldn't be encrypted in an even block
	memcpy(out_pos, in + i, in_size - i);

	return (out_pos - out) + (in_size - i);
}
