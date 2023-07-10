/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage 5 - Generate valid main_hash
*	
* This will differ from the main_hash originally used to protect the program,
* as unused values are unrecoverable and different combinations of alphanumeric
* strings can be used to generate the same hash and key values
* 
* It can be used to generate a key file which is valid except for RSA encryption,
* which must always be bypassed since the private keys are not recoverable from
* the public keys
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <vector>
#include "pin.H"
#include "../tea.h"
#include "stagemgr.h"

class stage5 : public stage
{
public:
	stage5(stage_mgr& mgr) : stage(mgr) { }

	// Start Stage
	void init(ADDRINT input) override;

	// Instruction call handlers
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt) {}
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) {}
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) {}
};

