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

#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>
#include "pin.H"
#include "../utils.h"
#include "../insinfo.h"
#include "../licdetails.h"
#include "stage2.h"

// Start Stage
void stage2::init(ADDRINT input)
{
	logfile << "Stage 2 -- Finding and bypassing hash_3\n\n";

	// RSA decrypted license buffer
	dec_lic = input;

	// Grab our license file's hash_3 value
	hash3 = rword(dec_lic + 0x33);

	// Start sub-staging for this stage
	logfile << "Searching for hash_3 comparison..." << std::endl;
	sub_stage = 1;
}

/********************
*  Call handlers -- coordinate sub-stages
*********************/

// General instruction callback handler
VOID stage2::process_ins(ADDRINT addr, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 2:
		find_hash_cmp(addr, ctxt);
		return;
	case 3:
		// Stage 2 done
		sub_stage = STAGE_INACTIVE;

		// Advance to next stage
		// Stage 3 needs the decrypted license buffer
		mgr.advance(dec_lic);
	}
}

// Read instruction callback handler
VOID stage2::process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 1:
		find_hash_read(addr, ea, size, ctxt);
	}
}

/********************
*  Sub-stages
*********************/

// 1 -- Find where hash_3 is read from the decrypted license buffer
// This won't be the cmp instruction. WL likes to read a value then push and pop
// it over and over before it eventually makes its way to the instruction that uses it
// This just narrows down our search space
VOID stage2::find_hash_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if ((ea == dec_lic + 0x33) && (size == 2))
	{
		logfile << "hash_3 read by " << addr << std::endl;
		sub_stage = 2;
	}
}

// 2 -- Find hash_3 comparison
VOID stage2::find_hash_cmp(ADDRINT addr, CONTEXT* ctxt)
{
	// Looking for a specific form of 'cmp word ptr [reg1], reg2'
	if (ii::isWordPtrRegCmp(addr))
	{
		// Get the values being compared
		uint16_t mem_val = rword(PIN_GetContextReg(ctxt, ii::WordPtrRegCmp_memreg(addr)));
		uint16_t reg_val = PIN_GetContextReg(ctxt, ii::WordPtrRegCmp_genreg(addr));
		
		// This is almost certainly the cmp we are looking for, and I'm fairly certain
		// the value from our license file vs the correct value are always in the same relative places
		// But given that the specific registers used here vary from version to version,
		// we're going to excersice an abundance of caution and make sure at least one comparison value is
		// the one we made up, and that we save the value it's being compared against (if different) instead of our own
		if (mem_val != hash3)
		{
			if (reg_val != hash3)
				return;	// Neither of these is the value from our license file, we'll keep looking
			else
				hash.hash_3 = mem_val;	// Saving whichever comparison value isn't the one we generated
		}
		else
			hash.hash_3 = reg_val;		// Ditto

		logfile << "Found hash_3: " << hash.hash_3 << std::endl;
		logfile << "Bypassing check\n" << std::endl;

		sub_stage = 3;

		// Make the comparison always pass
		// Set flags for comparison passing
		PIN_SetContextReg(ctxt, REG_EFLAGS, 0x200242);

		// Advance to next instruction
		// 'cmp word ptr [reg1], reg2' is a 3-byte instruction unless esp or ebp are involved
		// which they never should be unless ii::isWordPtrRegCmp didn't do its job
		PIN_SetContextReg(ctxt, REG_INST_PTR, addr + 3);
		PIN_ExecuteAt(ctxt);
	}
}
