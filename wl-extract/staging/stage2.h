/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage 2 - Find hash_3
*
* A 2-byte value in our license file is compared to a stored value
* We track down the comparison, force it to pass, and log the correct value
*
********************************************************************************/

#pragma once
#include <cstdint>
#include "pin.H"
#include "stagemgr.h"

class stage2 : public stage
{
private:
	ADDRINT dec_lic;	// RSA decrypted buffer address
	uint16_t hash3;		// hash_3 from our license

public:
	stage2(stage_mgr& mgr) : stage(mgr), dec_lic(0), hash3(0) { }

	// Start Stage
	void init(ADDRINT input) override;

	// Instruction call handlers
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt);
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) {}

	// Sub-stages

	// 1 -- Find where hash_3 is read from the decrypted license buffer
	VOID find_hash_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 2 -- Find hash comparison 'cmp word ptr [reg1], reg2'
	VOID find_hash_cmp(ADDRINT addr, CONTEXT* ctxt);
};
