/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage 3 - Find password
*
* The beginning of the password routine is easily found via a reference to a constant,
* then the password can be found by checking memory reads for potentially valid strings
* and decrypting part of our license data with them to make sure we get the same output
*
********************************************************************************/

#pragma once
#include <cstdint>
#include "pin.H"
#include "stagemgr.h"

class stage3 : public stage
{
private:
	ADDRINT dec_lic;	// RSA decrypted buffer address
	uint32_t rsa_dec;	// First RSA-decrypted DWORD - used to verify discovered password

public:
	stage3(stage_mgr& mgr) : stage(mgr), dec_lic(0) { }

	// Start Stage
	void init(ADDRINT input) override;

	// Instruction call handlers
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt);
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// Sub-stages

	// 1 - Find password decryption routine
	VOID find_pw_decrypt(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 2 - Password search
	VOID find_password(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 3 - Pasword verification
	VOID verify_pw(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
};
