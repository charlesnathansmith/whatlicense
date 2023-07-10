/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage 1 - RSA Bypass
*
* Looks for the license data copy being read and backtracks to find mp_exptmod
* and patch in the correct RSA public keys needed for our license file
* 
* RSA decryption and verification aren't virtualized like most of the protection
* mechanism (the related functions were probably statically linked in from libtomcrypt)
* There is still some variation between builds, but we can rely on a known memory layout and
* general instruction layout to feel our way around here in a way we're unable to in other stages
* 
********************************************************************************/

#pragma once
#include "pin.H"
#include "stagemgr.h"

class stage1 : public stage
{
private:
	// Number of sections to decrypt
	size_t dec_sections;

	// Important instruction addresses
	ADDRINT ret_to_rsaexptmod, mp_exptmod_addr;

	// Important data addresses
	ADDRINT pre_rsa_buf, key_tmp_ref, dec_lic;

public:
	stage1(stage_mgr& mgr) : stage(mgr), dec_sections(0), ret_to_rsaexptmod(0),
		mp_exptmod_addr(0), pre_rsa_buf(0), key_tmp_ref(0), dec_lic(0) { }

	// Start stage
	void init(ADDRINT input) override;

	// Instruction callback handlers
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt);
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) {}

	// Sub-stages

	// 1 - Find the first read of the encrypted license
	VOID find_enclic_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 2 - Find where execution returns into rsa_exptmod
	VOID traceback_to_rsaexptmod(ADDRINT addr, CONTEXT* ctxt);

	// 3 - Count reads of a local key pointer to find mp_exptmod address
	VOID skip_keyptr_refs(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 4 - Find the address of mp_exptmod
	VOID find_mp_exptmod(ADDRINT addr, CONTEXT* ctxt);

	// 5 - mp_exptmod hook to hotswap RSA keys
	VOID mp_exptmod_handler(ADDRINT addr, CONTEXT* ctxt);
};
