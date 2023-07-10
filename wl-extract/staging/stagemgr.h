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
#include "../licdetails.h"
#include "pin.H"

constexpr size_t STAGE_INACTIVE = 0;

class stage;

// Stage manager
// Forwards instruction analysis callbacks to the currently active stage
class stage_mgr
{
private:
	std::vector<stage*> stages;	// Pointers to all the stages being managed
	size_t cur;					// The current active stage

	std::ofstream &logfile;		// Reference to the output logfile
	lic_details &lic_det;		// License file details
	OS_THREAD_ID thread;		// Everything we care about happens in the same thread
	main_hash hash;				// The recovered main_hash we are sequentially building
	bool _attached;				// If true, we should keep actively instrumenting every instruction

public:
	stage_mgr(std::ofstream& logfile, lic_details& lic_det) :
		cur(0), logfile(logfile), lic_det(lic_det), thread(0), _attached(true) { }

	// Loads all stages into the stage vector
	void init(OS_THREAD_ID main_thread);

	// Advances to the next stage
	// Input type depends on infromation that stage needs from the previous one
	bool advance(ADDRINT input);
	
	// Analysis calls
	// Will be forwarded to currently active stage
	VOID process_ins(ADDRINT addr, CONTEXT* ctxt);
	VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);
	VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt);

	// Accessors
	OS_THREAD_ID get_thread() const { return thread;  }
	std::ofstream& get_logfile() { return logfile; }
	lic_details& get_lic_det() { return lic_det; }
	main_hash& get_hash() { return hash;  }
	size_t get_stage() const { return cur; }
	bool attached() const { return _attached; }
	void detach() { _attached = false; }
};

// Base class for analysis stages
class stage
{
protected:
	stage_mgr& mgr;			// Reference to the parent stage manager
	size_t sub_stage;		// Current sub-stage that's active

	std::ofstream& logfile;	// Reference to the output logfile
	lic_details& lic_det;	// License file details
	OS_THREAD_ID thread;	// Everything we care about happens in the same thread
	main_hash &hash;		// The recovered main_hash we are sequentially building

public:
	stage(stage_mgr& mgr, ADDRINT input = 0) :
		mgr(mgr), logfile(mgr.get_logfile()), lic_det(mgr.get_lic_det()),
		thread(mgr.get_thread()), hash(mgr.get_hash()), sub_stage(STAGE_INACTIVE) {}

	// Initialize stage
	virtual void init(ADDRINT input) = 0;

	// Instruction call handlers
	virtual VOID process_ins(ADDRINT addr, CONTEXT* ctxt) = 0;
	virtual VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) = 0;
	virtual VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) = 0;
};
