/****************************************
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
****************************************/

#include <map>
#include "utils.h"
#include "insinfo.h"
#include "pin.H"

namespace ii
{
	// Is this instruction a specific type of immediate call (E8 xx xx xx)
	bool isE8Call(ADDRINT addr)
	{
		return (rbyte(addr) == 0xE8);
	}

	// Get destination of an E8 immediate call
	ADDRINT E8CallDest(ADDRINT addr)
	{
		return isE8Call(addr) ? (addr + 5 + rdword(addr + 1)) : 0;
	}

	// If this is a specific comparison type ("cmp word ptr [reg1], reg2")
	// without modifiers (eg. no "cmp word ptr [reg*8 + 2]" etc.)
	// and reg1 not esp or ebp
	bool isWordPtrRegCmp(ADDRINT addr)
	{
		if (rword(addr) == 0x3966)	// Has the correct opcode (66 39)
		{
			uint8_t mod_rm = rbyte(addr + 2);

			if (!(mod_rm & 0xc0) &&			// 0xc0 = 11000000
				((mod_rm & 0x07) != 0x04))	// != xxxxx100
				return true;
		}

		return false;
	}

	// Is instruction "shr dword ptr [reg], cl"
	bool isShrDwordPtr(ADDRINT addr)
	{
		// Opcode D3 covers shl, shr, ror, etc. on mem and regs
		// shr dword ptr selected with mod_rm xx101xxx
		return ((rbyte(addr) == 0xD3) && (rbyte(addr + 1) >> 3 == 5));
	}

	const LEVEL_BASE::REG regs[] = { REG_EAX, REG_ECX, REG_EDX, REG_EBX, REG_ESP, REG_EBP, REG_ESI, REG_EDI };

	// Returns memory register reg1 when used on "cmp word ptr [reg1], reg2"
	LEVEL_BASE::REG WordPtrRegCmp_memreg(ADDRINT addr)
	{
		// Memory register in 3 least sig bits 00000xxx of mod_rm
		// regs[mod_rm & 00000111]
		return regs[rbyte(addr + 2) & 0x7];
	}

	// Returns comparison register reg2 when used on "cmp word ptr [reg1], reg2"
	LEVEL_BASE::REG WordPtrRegCmp_genreg(ADDRINT addr)
	{
		// Comparison register in 00xxx000 of mod_rm
		// regs[(mod_rm & 00111000) >> 3]
		return regs[(rbyte(addr + 2) & 0x38) >> 3];
	}
}