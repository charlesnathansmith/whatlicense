/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Instruction inspection tools
*
* PIN doesn't provide a straightforward way to inspect instructions outside
* of the instruction instrumentation function, but we need that information
* inside of some analysis routines
*
* We can either inspect them at instrumentation time and pass it to every single call,
* build maps of instruction types, or just implement the inspections we need ourselves
*
* The latter is a lot more efficient, if not idiomatic PIN usage
*
* These are not generalized like PIN's inspection routines, and work only with the
* specific instruction types we need to find here
*
* We try to avoid dealing with individual instructions as much as possible because of
* how the virtualization can affect them, but these specific instruction types are consistent
* across versions
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <map>
#include "utils.h"
#include "pin.H"

namespace ii
{
	// Is instruction a specific type of immediate call (E8 xx xx xx)
	bool isE8Call(ADDRINT addr);

	// Get destination of an E8 immediate call
	ADDRINT E8CallDest(ADDRINT addr);

	// Is this is a specific comparison type ("cmp word ptr [reg1], reg2")
	// without modifiers (eg. no "cmp word ptr [reg*8 + 2]" etc.)
	// and reg1 not esp or ebp
	bool isWordPtrRegCmp(ADDRINT addr);

	// Is instruction "shr dword ptr [reg], cl"
	bool isShrDwordPtr(ADDRINT addr);

	// Returns memory register reg1 when used on "cmp word ptr [reg1], reg2"
	LEVEL_BASE::REG WordPtrRegCmp_memreg(ADDRINT addr);

	// Returns comparison register reg2 when used on "cmp word ptr [reg1], reg2"
	LEVEL_BASE::REG WordPtrRegCmp_genreg(ADDRINT addr);
}
