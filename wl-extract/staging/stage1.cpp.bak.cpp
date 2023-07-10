/****************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  Hash extraction tool
*   Stage 1 - RSA Bypass
*
****************************************/

#include <cstdint>
#include <iostream>
#include <fstream>
#include <string>
#include "pin.H"
#include "../utils.h"
#include "../insinfo.h"
#include "../licdetails.h"
#include "stage1.h"

void stage1::init(ADDRINT input)
{
	logfile << "Stage 1 -- RSA Bypass\n\n";

	// RSA encrypted buffer
	pre_rsa_buf = input;

	// Calculate number of calls to mp_exptmod required to decrypt the buffer
	dec_sections = lic_det.size / 0x80;

	logfile << "dec_sections: " << dec_sections << std::endl;

	// Start sub-staging for this stage
	sub_stage = 1;

	logfile << "Searching for mp_exptmod..." << std::endl;
}

/********************
*  Call handlers -- coordinate sub-stages
*********************/

VOID stage1::process_ins(ADDRINT addr, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 2:
		traceback_to_rsaexptmod(addr, ctxt);
		return;
	case 4:
		find_mp_exptmod(addr, ctxt);
		return;
	case 5:
		mp_exptmod_handler(addr, ctxt);
		return;
	case 6:
		// Advance to next stage
		// Stage 2 needs the RSA-decrypted license buffer address we found
		sub_stage = STAGE_INACTIVE;
		mgr.advance(dec_lic);
	}
}

VOID stage1::process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (PIN_GetTid() != thread)
		return;

	switch (sub_stage)
	{
	case STAGE_INACTIVE:
		return;
	case 1:
		find_enclic_read(addr, ea, size, ctxt);
		return;
	case 3:
		skip_keyptr_refs(addr, ea, size, ctxt);
		return;
	}
}

/********************
*  Sub-stages
*********************/

// 1 - Find the first read of the encrypted license,
// (occurs inside of libtomcrypt's mp_read_unsigned_bin)
VOID stage1::find_enclic_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (ea == pre_rsa_buf)
	{
		// We need to trace execution back into rsa_exptmod and ultimately
		// to mp_expmod so we can hotswap the RSA keys
		logfile << "License copy read at: " << std::hex << addr << " (inside mp_read_unsigned_bin)" << std::endl;
		
		ret_to_rsaexptmod = rdword(PIN_GetContextReg(ctxt, REG_ESP) + 8);
		logfile << "Return to rsa_exptmod: " << ret_to_rsaexptmod << std::endl;

		sub_stage = 2;
	}
}

// 2 - Find where execution returns into rsa_exptmod
VOID stage1::traceback_to_rsaexptmod(ADDRINT addr, CONTEXT* ctxt)
{
	if (addr == ret_to_rsaexptmod)
	{
		logfile << "Back in rsa_exptmod at: " << addr << std::endl;

		// Save address of destination buffer for RSA decrypted license
		dec_lic = rdword(PIN_GetContextReg(ctxt, REG_ESP) + 0x8c);
		logfile << "Rsa decrypted license destination: " << dec_lic << std::endl;

		// Save address of a local RSA key pointer that we can
		// count reads of in order to find the call to mp_exptmod
		key_tmp_ref = PIN_GetContextReg(ctxt, REG_EBP) + 0x1c;

		sub_stage = 3;
	}
}

// 3 - Count reads of local key pointer found earlier
VOID stage1::skip_keyptr_refs(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (ea == key_tmp_ref)
	{
		static size_t exptmod_search_count = 0;

		logfile << "[ebp+0x1c] read at " << addr << std::endl;

		// After it is read twice, the next "call" will be to mp_exptmod
		// This is consistent across versions, while tring to directly calculate
		// mp_exptmod's address isn't from anything we already know isn't
		if (exptmod_search_count++ > 0)
			sub_stage = 4;
	}
}

// 4 - Find the address of mp_exptmod
VOID stage1::find_mp_exptmod(ADDRINT addr, CONTEXT* ctxt)
{
	// Start searching for a specific type of immediate valued call
	if (ii::isE8Call(addr))
	{
		mp_exptmod_addr = ii::E8CallDest(addr);
		logfile << "Found mp_exptmod: " << mp_exptmod_addr << '\n' << std::endl;

		sub_stage = 5;
	}
}

// Log an mp_digit (large integer format from libtommath)
VOID mp_print(std::ofstream& logfile, const mp_int* const mp)
{
	mp_digit* dp = mp->dp;

	for (size_t i = 0; i < mp->used; i++)
		logfile << dp[i] << ' ';

	logfile << std::endl;
}

// 5 - mp_exptmod hook to hotswap RSA keys
VOID stage1::mp_exptmod_handler(ADDRINT addr, CONTEXT* ctxt)
{
	if (addr != mp_exptmod_addr)
		return;

	ADDRINT esp = PIN_GetContextReg(ctxt, REG_ESP);

	// rsa_public_2 is to used decrypt the license in segments
	// then rsa_public_1 is used to verify the signature
	static size_t count = 0;

	// Get key component arguments
	mp_int **e = (mp_int**) (esp + 8);
	mp_int **N = (mp_int**) (esp + 0xc);

	if (count < dec_sections)
	{
		static bool logged_pk2 = false;
		
		if (!logged_pk2)
		{
			// Log original key stored in protected program
			logfile << "Swapping rsa_public_key2\n";
			logfile << "Stored (mp_int digits):\nexp:\t";
			mp_print(logfile, *e);
			logfile << "mod:\t";
			mp_print(logfile, *N);
			logfile << std::endl;

			logged_pk2 = true;
		}

		rdword(esp + 8)   = (ADDRINT) lic_det.rsa_key_2.exp();
		rdword(esp + 0xc) = (ADDRINT) lic_det.rsa_key_2.n();

		logfile << "New (mp_int digits):\nexp:\t";
		mp_print(logfile, *e);
		logfile << "mod:\t";
		mp_print(logfile, *N);
		logfile << std::endl;
	}
	else
	{
		logfile << "Swapping rsa_public_key1\n";
			
		// Log original key stored in protected program
		logfile << "Stored (mp_int digits):\nexp:\t";
		mp_print(logfile, *e);
		logfile << "mod:\t";
		mp_print(logfile, *N);

		logfile << std::endl;

		rdword(esp + 8)   = (ADDRINT) lic_det.rsa_key_1.exp();
		rdword(esp + 0xc) = (ADDRINT) lic_det.rsa_key_1.n();

		sub_stage = 6;
	}
	
	count++;
}
