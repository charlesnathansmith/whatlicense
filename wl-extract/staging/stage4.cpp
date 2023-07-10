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

#include <cstdint>
#include <fstream>
#include "pin.H"
#include "../utils.h"
#include "../insinfo.h"
#include "../tea.h"
#include "stage4.h"

// Start Stage
void stage4::init(ADDRINT input)
{
	logfile << "Stage 4 -- Solving TEA key\n\n";

	// Password decrypted license buffer
	dec_lic = input;
	
	// Set sums used to calculate each intermediate
	// The result of the last half-round is difficult to collect reliably
	// So we don't use the last set of half-round data for intermed[1]
	for (size_t sum = 0x9e3779b9 * 12; sum != 0; sum -= 0x9e3779b9)
	{
		intermed[0].push_back(tea_half_round(sum));

		// Can't capture the last half round the same way as the others
		// Should have plenty of data to solve keys without it
		if (sum != 0x9e3779b9)
			intermed[1].push_back(tea_half_round(sum));
	}
	
	// Fill in initial values
	intermed[0][0].a = rdword(dec_lic);
	intermed[0][0].b = rdword(dec_lic + 4);

	// Start sub-staging for this stage
	logfile << "Searching for TEA decryption routine..." << std::endl;
	sub_stage = 1;
}

/********************
*  Call handlers -- coordinate sub-stages
*********************/

// General instruction callback handler
VOID stage4::process_ins(ADDRINT addr, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;

	case 2:
		solve_tea_key(addr, ctxt);
		return;

	case 3:
		// Advance to next stage
		sub_stage = STAGE_INACTIVE;
		mgr.advance(0);
	}
}

// Read instruction callback handler
VOID stage4::process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;

	case 1:
		find_tea_intermeds(addr, ea, size, ctxt);
	}
}

/********************
*  Sub-stages
*********************/

// 1 - Collect intermediate data
VOID stage4::find_tea_intermeds(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	// Only looking for 'shr dword ptr [reg], 5'
	if ((size != 4) ||
		!ii::isShrDwordPtr(addr) ||
		(PIN_GetContextReg(ctxt, REG_ECX) & 0xff) != 5)
		return;

	static bool logging = false;

	// There are two sets of half-round data being collected,
	// and the availability of it alternates back and forth
	// 
	// idx is incremented after each value is recovered so that:
	// idx % 2 = current data set (intermed[0] or intermed[1])
	// idx / 2 = index within the data set
	static size_t idx = 0;

	// First round found -- The first known 'a' value from our license file is getting used in calculations
	if (!logging && (rdword(ea) == intermed[0][0].a))
	{
		logfile << "TEA decryption routine found near " << addr << '\n';
		logfile << "Collecting intermediate values..." << std::endl;
		logging = true;
		return;
	}

	if (logging)
	{
		// None of this is going to make any sense without understanding https://github.com/charlesnathansmith/teasolver
		// We were only trying to solve half a round there, but here we need information about both halves,
		// and the input to one is the solution to the one before it, and there are two different data sets
		// we're alternating between collecting data

		// If we made it to here, then we're analyzing a 'shr dword ptr [reg], 5' instruction
		// rdword(ea) is going to be the value of whatever '[reg]' is pointing to
		// The first time we get here, we are in the 2nd half of the first decryption round
		// 
		// It's really convoluted to catch the first half of the first decryption round, so we don't bother
		// because 'a' and 'b' for the very first half-round are just pulled from the input buffer and we also know 'sum'
		// 
		// The first value we encounter getting the >>5 treatment here will be b_prime for the very first half-round,
		// as well as the 'a' value going into the second half of the first round
		//
		// As we keep collecting values, each will be the b_prime solution to the previous half-round,
		// the 'a' input to the current half-round, and the 'b' input to the next half-round
		intermed[idx % 2][idx / 2].b_prime = rdword(ea);
		uint32_t next_b = intermed[idx % 2][idx / 2].a;

		if (++idx >= (12 * 2) - 1)
		{
			sub_stage = 2;
			return;
		}

		intermed[idx % 2][idx / 2].a = rdword(ea);
		intermed[idx % 2][idx / 2].b = next_b;
	}
}

// 2 - Use intermediate data to solve the TEA key
VOID stage4::solve_tea_key(ADDRINT addr, CONTEXT* ctxt)
{
	// Try to solve for TEA key assuming 12-round decryption
	if (!tea_solver(intermed[1], hash.tea_key) ||
		!tea_solver(intermed[0], &hash.tea_key[2]))
	{
		logfile << "Unable to find TEA key" << std::endl;

		if (lic_det.skip_hwid && !lic_det.launch_mode)
			PIN_ExitApplication(-1);
	}
	else
	{
		logfile << "TEA key found: ";

		for (size_t i = 0; i < 4; i++)
			logfile << hash.tea_key[i] << ' ';

		logfile << '\n' << std::endl;
	}

	sub_stage = 3;
}
