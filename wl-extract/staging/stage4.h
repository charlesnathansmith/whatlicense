/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage 4 - Solve TEA keys
*
* WL performs 12 rounds of TEA-like decryption on the first two dwords of
* the password decrypted buffer
*
* The keys are never directly used (they're mathematically shadowed),
* but we can collect the intermediate values and solve for them
*
* See https://github.com/charlesnathansmith/teasolver for a lengthy
* break down of the solving process
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <vector>
#include "pin.H"
#include "../tea.h"
#include "stagemgr.h"

class stage4 : public stage
{
private:
	// Intermediate half-round data
	// intermed[0] holds intermediate values collected for key2, key3 pair
	// intermed[1] holds intermediate values collected for for key0, key1 pair
	tea_intermed intermed[2];
	
	size_t count;		// Current intermediate entry we're working on
	ADDRINT dec_lic;	// Password decrypted buffer address

public:
	stage4(stage_mgr& mgr) : stage(mgr), count(0), dec_lic(0) { }

	// Start Stage
	void init(ADDRINT input) override;

	// Instruction call handlers
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt);
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) {}

	// Sub-stages

	// 1 - Collect intermediate data
	VOID find_tea_intermeds(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// 2 - Use intermediate data to solve the TEA key
	VOID solve_tea_key(ADDRINT addr, CONTEXT* ctxt);
};
