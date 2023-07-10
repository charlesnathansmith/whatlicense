/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Stage Manager
*
* Manages analysis stages
*
* Each major goal we need to accomplish gets its own stage
* to manage all of the analysis functions needed to that end
*
* We need to procedurally work with data we can only receive through callbacks,
* so 'stage_mgr' and the derived 'stage' classes work together to implement a
* state machine, allowing everything to be broken down into managable chunks
*
********************************************************************************/
#pragma once
#include <cstdint>
#include <vector>
#include "../hash.h"
#include "stagemgr.h"
#include "stage1.h"
#include "stage2.h"
#include "stage3.h"
#include "stage4.h"
#include "stage5.h"

// Load stages
void stage_mgr::init(OS_THREAD_ID main_thread)
{
	// Should only be initialized once
	if (!stages.size())
	{
		thread = main_thread;

		// If we had 100 stages, there's probably some meta-programming magic we could do to simplify this
		// But it'll do for our purposes
		stages.push_back(new stage1(*this));
		stages.push_back(new stage2(*this));
		stages.push_back(new stage3(*this));
		stages.push_back(new stage4(*this));
		stages.push_back(new stage5(*this));
	}
}

// Advance to the next stage
bool stage_mgr::advance(ADDRINT input)
{
	// Don't try to advance to stages we don't have
	if (++cur > stages.size())
	{
		cur--;
		return false;
	}

	// Start the next stage
	// We started labeling the stages from 1 and they're in a 0-indexed vector,
	// so 'cur - 1' is just a correction for that
	// Maybe it would've been more sensible to label them from 0,
	// but finding the license mapping is sort of "Stage 0" and stage_mgr doesn't handle that part
	stages[cur - 1]->init(input);
	return true;
}

// Forwards general instruction analysis callback to the currently active stage
VOID stage_mgr::process_ins(ADDRINT addr, CONTEXT* ctxt)
{
	if (cur > stages.size())
		return;

	stages[cur - 1]->process_ins(addr, ctxt);
}

// Forwards read instruction analysis callback to the currently active stage
VOID stage_mgr::process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (cur > stages.size())
		return;

	stages[cur - 1]->process_read(addr, ea, size, ctxt);
}

// Forwards write instruction analysis callback to the currently active stage
VOID stage_mgr::process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt)
{
	if (cur > stages.size())
		return;

	stages[cur - 1]->process_write(addr, ea, size, ctxt);
}
