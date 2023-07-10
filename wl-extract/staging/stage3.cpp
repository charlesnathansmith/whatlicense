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

#include <cstdint>
#include <fstream>
#include <string>
#include "pin.H"
#include "../utils.h"
#include "../insinfo.h"
#include "../password.h"
#include "stage3.h"

// Start Stage
void stage3::init(ADDRINT input)
{
	logfile << "Stage 3 -- Finding password\n\n";

	// RSA decrypted license buffer
	dec_lic = input;

	// Save first dword of license before password decrypt to verify discovered password
	rsa_dec = rdword(dec_lic);

	// Start sub-staging for this stage
	sub_stage = 1;

	logfile << "Searching for password decrypt routine..." << std::endl;
}

/********************
*  Call handlers -- coordinate sub-stages
*********************/

// General instruction callback handler
VOID stage3::process_ins(ADDRINT addr, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 4:
		// Advance to next stage
		sub_stage = STAGE_INACTIVE;
		mgr.advance(dec_lic);
	}
}

// Read instruction callback handler
VOID stage3::process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 1:
		find_pw_decrypt(addr, ea, size, ctxt);
	}
}

// Write instruction callback handler
VOID stage3::process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 2:
		find_password(addr, ea, size, ctxt);
		return;
	case 3:
		verify_pw(addr, ea, size, ctxt);
	}
}

/********************
*  Sub-stages
*********************/

// 1 - Find password decryption routine
VOID stage3::find_pw_decrypt(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	// Check for read of hard-coded constant only used during password decryption
	if ((size == 1) && (rdword(ea) == 0x41363233))
	{
		logfile << "Password decrypt routine found near " << addr << std::endl;
		logfile << "Searching for password..." << std::endl;
		sub_stage = 2;
	}
}

// 2 - Password search
VOID stage3::find_password(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	// Check 4-byte writes for pointers to a validly formatted password
	// This is really inefficient but reliable, since we can't assume much about
	// the memory layout or instructions being executed here, but a pointer to
	// the password will get written at some point in here and I've yet to encounter
	// any false positives.
	// 
	// If encountering false positives is suspected, you can just store all matches
	// and verify them in turn at the end, but this hasn't proved necessary yet

	// Only checking 4-byte writes
	if (size != 4)
		return;

	char pw[33];

	if (PIN_SafeCopy(pw, (VOID*) rdword(ea), 32) != 32)
		return;

	// Verify valid password format -- must be a 32-byte alphanumeric string
	for (size_t i = 0; i < 32; i++)
		if (!isalnum(pw[i]))
			return;

	pw[32] = '\0';

	logfile << "Password found: " << pw << std::endl;
	hash.password = pw;

	sub_stage = 3;
}

// 3 - Pasword verification
VOID stage3::verify_pw(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{	
	// Uses the candidate password to decrypt the first dword of our license
	// and compare it to the protected program's decryption result

	// Check for last dword of the buffer being decryped
	if ((size == 4) && (ea == dec_lic + 0x2c))
	{
		logfile << "Verifying password... ";
		logfile.flush();

		uint32_t in  = rsa_dec;
		uint32_t out = rdword(dec_lic);

		if (pw_encrypt(in, hash.password.c_str()) == out)
			logfile << "valid\n" << std::endl;
		else
			logfile << "invalid\n" << std::endl;

		sub_stage = 4;
	}		
}
