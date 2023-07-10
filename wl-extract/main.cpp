/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
* 
*  wl-extract
*  main_hash extraction tool
*   Main
* 
* Sets up intrumentation
* 
* Locates where license file gets mapped into memory
* and copied to before beginning the staging sequence in earnest,
* then hands off analysis to the stage manager
* 
* Also hooks error messages to extract HWID and watch for anti-debug tripping
*
****************************************/

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <initializer_list>
#include <stdlib.h>
#include "pin.H"
#include "ntdef.h"
#include "utils.h"
#include "licdetails.h"
#include "staging/stagemgr.h"
#include <stdlib.h>

/********************
*  Command line options
*********************/

// Output log file
KNOB<std::string> log_filename(KNOB_MODE_WRITEONCE, "pintool", "o", "wl_log.txt", "[out] Log file");

// Dummy license key file created by wl-lic
KNOB<std::string> regkey_dat(KNOB_MODE_WRITEONCE, "pintool", "d", "regkey.dat", "License key file");

// License key file RSA info file created by wl-lic
KNOB<std::string> regkey_rsa(KNOB_MODE_WRITEONCE, "pintool", "r", "regkey.rsa", "License RSA file");

// Run in launch mode
KNOB<BOOL> launch_mode(KNOB_MODE_WRITEONCE, "pintool", "l", "0", "Run in launch mode");

// Skip HWID detection
KNOB<BOOL> skip_hwid(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "Skip searching error messages for HWID");

/********************
* Globals
*********************/

// Output filestream
std::ofstream logfile;

// License file details
lic_details lic;

// Everything relevant happens in main thread
OS_THREAD_ID main_thread = 0;

// Clipboard data locking functions
ADDRINT GlobalLock = 0, GlobalUnlock = 0;

/********************
* Initialize stage manager
*********************/
stage_mgr mgr(logfile, lic);

// Static instrumentation call forwarding routines
VOID process_ins(ADDRINT addr, CONTEXT* ctxt) { mgr.process_ins(addr, ctxt); }
VOID process_read(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) { mgr.process_read(addr, ea, size, ctxt); }
VOID process_write(ADDRINT addr, ADDRINT ea, UINT32 size, CONTEXT* ctxt) { mgr.process_write(addr, ea, size, ctxt); }

/********************
*  Find initial license mapping and copy location
*********************/

// Is license mapped into memory?
bool lic_mapped = false;

// Potential locations of license file copy
std::set<ADDRINT> copy_set;

// License file copy location
ADDRINT lic_copy = 0;

// NtCreateFile hook
// Redirects attempt to open original license file location to the supplied license file
VOID NtCreateFile_before(ADDRINT esp)
{
    // Get ObjectAttributes pointer from arguments
    OBJECT_ATTRIBUTES *ObjectAttributes = *((OBJECT_ATTRIBUTES**)(esp + 0xc));

    if (ObjectAttributes && ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer)
    {
        std::wstring wpath(ObjectAttributes->ObjectName->Buffer);
        std::string path(wpath.begin(), wpath.end());
        
        if (string_endswith(path, "regkey.dat") && (path != lic.nt_path))
        {
            logfile << "Original license path:\t" << path << std::endl;

            // The main thread we care about loads the license file
            main_thread = PIN_GetTid();

            logfile << "main_thread: " << std::hex << main_thread << std::endl;

            // Redirect to supplied license file path
            size_t path_len = lic.nt_path.size();
            ObjectAttributes->ObjectName->Length = path_len * 2;
            ObjectAttributes->ObjectName->MaximumLength = (path_len + 1) * 2;

            // Path needs to be wide char
            wchar_t *path = new wchar_t[path_len + 1];
            mbstowcs(path, lic.nt_path.c_str(), path_len + 1);

            // Either the original path buffer or the new one will be left dangling
            // depending on how UNICODE_STRING gets cleaned up later
            // This is a one-off, so we'll take the leak over creating a potential double-free
            ObjectAttributes->ObjectName->Buffer = path;

            logfile << "New license path:\t" << lic.nt_path << std::endl;
        }
    }
}

// MapViewOfFile hook
// Finds where our license file gets intially mapped into memory
void* MapViewOfFile_hook(AFUNPTR MapViewOfFile_orig, ADDRINT ret_addr, CONTEXT *ctxt,
    HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
    DWORD dwFileOffsetLow, size_t dwNumberOfBytesToMap)
{
    void *ret;

    // Call the real MapViewOfFile
    PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_STDCALL, MapViewOfFile_orig, NULL, PIN_PARG(void*), &ret,
        PIN_PARG(HANDLE),   hFileMappingObject,
        PIN_PARG(DWORD),    dwDesiredAccess,
        PIN_PARG(DWORD),    dwFileOffsetHigh,
        PIN_PARG(DWORD),    dwFileOffsetLow,
        PIN_PARG(size_t),   dwNumberOfBytesToMap,
        PIN_PARG_END());

    // Compare first 8 bytes of mapped file to see if it's our license
    char mapped[8];

    if ((PIN_SafeCopy(mapped, ret, 8) == 8) && !memcmp(mapped, lic.head.c_str(), 8))
    {
        logfile << "License file mapped to: " << std::hex << (ADDRINT)ret << std::endl;
        lic_mapped = true;
    }

    return ret;
}

// Mapped license file will be copied to a new memory location 1 byte at a time
// We log potential start locations written to while it is mapped
// These will be searched for the license data copy after original file is unmapped
// There will only be a handful of hits so this isn't as wildly inefficient as it may seem
VOID record_license_copy(ADDRINT ea)
{
    // Log all addresses where first byte of regkey data is written during copy loop
    // One of these will be the start of the copied license data
    if (lic_mapped && (PIN_GetTid() == main_thread) && (rbyte(ea) == (lic.head[0] & 0xff)))
        copy_set.insert(ea);
}

// UnmapViewOfFile hook
// Search for license data copy location after license file is unmapped
VOID UnmapViewOfFile_before(ADDRINT esp)
{
    if (lic_mapped && (PIN_GetTid() == main_thread))
    {
        char mapped[8];
        
        // Grab the first 8 bytes of the data being unmapped
        if (PIN_SafeCopy(mapped, (void *) rdword(esp+4), 8) != 8)
            return;

        // Compare the beginning of the data being unmapped to the license file data
        if (!memcmp(mapped, lic.head.c_str(), 8))
        {
            // License file being unmapped
            // Copy to another location must be complete
            lic_mapped = false;

            char test[8];
            bool found = false;

            // Find license data copy location by searching potential start addresses
            for (auto& addr : copy_set)
            {
                if ((PIN_SafeCopy(test, (void*)addr, 8) == 8) &&
                    !memcmp(test, mapped, 8))
                {
                    found = true;
                    lic_copy = addr;
                    break;
                }
            }

            if (!found)
            {
                logfile << "Unable to find license data copy" << std::endl;
                PIN_ExitApplication(-1);
            }
            
            logfile << "License data copied to: " << lic_copy << '\n' << std::endl;

            // Clear the potential start address list since we're done with it
            copy_set.clear();

            // Initialize and pass control to stage manager
            mgr.init(main_thread);
            mgr.advance(lic_copy);
        }
    }
}

// MessageBoxExA hook to scan error messages for HWID and debugger warnings
VOID MessageBoxExA_before(ADDRINT esp)
{
    char *text = *((char**)(esp + 8)), *caption = *((char**)(esp + 0xc));

    if (!text || !caption)
        return;

    if (strstr(text, "ebug") || strstr(caption, "ebug"))
    {
        logfile << "Protected program appears to be complaining about a debugger being present\n";
            "wl-extract should not trigger detection except possibly on a very slow computer\n"
            "Make sure you don't have any common debuggers, Process Monitor, or other popular tools open,\n"
            "as WL's debugger detection actively searches for these types of processes.\n\n"
            "If the error persists, you may need to hook RDTSC and timeGetTime, which are not currently implemented\n\n";

        logfile << '\"' << caption << "\"\n\"" << text << "\"\n" << std::endl;
    }

    // The HWID search can be skipped using the -s option
    // This is much faster if you already know your HWID since we can exit the process
    // early after collecting all the other info we're after later
    if (!skip_hwid.Value())
    {
        char hwid[40];

        if (find_hwid(caption, hwid))
            logfile << "Potential HWID: " << hwid << std::endl;

        if (find_hwid(text, hwid))
            logfile << "Potential HWID: " << hwid << std::endl;
    }
}

// SetClipboardData hook to scan for HWID
VOID SetClipboardData_before(ADDRINT esp, CONTEXT* ctxt)
{
    // Is the clipboard data type CF_TEXT?
    if (GlobalLock && GlobalUnlock && (rdword(esp + 4) == 1))
    {
        char *data;

        // The data handle argument to SetClipboardData refers to a global (system wide) memory object
        // We have to use GlobalLock to get a pointer the real buffer, then GlobalUnlock to release access
        PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_STDCALL, (AFUNPTR) GlobalLock, NULL, PIN_PARG(char*), &data,
            PIN_PARG(HANDLE), (HANDLE) rdword(esp + 8),
            PIN_PARG_END());

        char hwid[40];

        if (data && find_hwid(data, hwid))
            logfile << "Potential HWID: " << hwid << std::endl;

        // GlobalUnlock to release access
        PIN_CallApplicationFunction(ctxt, PIN_ThreadId(), CALLINGSTD_STDCALL, (AFUNPTR)GlobalUnlock, NULL, PIN_PARG(bool), (bool*) &data,
            PIN_PARG(HANDLE), (HANDLE)rdword(esp + 8),
            PIN_PARG_END());
    }
}

// Instrument modules as they load
VOID imgInstrumentation(IMG img, VOID* val)
{
    if (!mgr.attached())
        return;

    const std::string& img_name = IMG_Name(img);

    if (string_endswith(img_name, "ntdll.dll"))
    {
        // Hook beginning of Nt/ZwCreateFile
        // It should be enough just to hook NtCreateFile but sometimes it doesn't catch it for whatever reason
        for (const char *rtn_name : { "ZwCreateFile", "NtCreateFile" })
        {
            RTN rtn = RTN_FindByName(img, rtn_name);

            if (rtn != RTN_Invalid())
            {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)NtCreateFile_before, IARG_REG_VALUE, REG_ESP, IARG_END);
                RTN_Close(rtn);
            }
        }
    }
    else if (string_endswith(img_name, "kernel32.dll"))
    {
        // Replace MapViewOfFile
        RTN rtn = RTN_FindByName(img, "MapViewOfFile");

        if (rtn != RTN_Invalid())
        {
            PROTO proto = PROTO_Allocate(PIN_PARG(void*), CALLINGSTD_STDCALL, "MapViewOfFile",
                PIN_PARG(HANDLE),   // hFileMappingObject
                PIN_PARG(DWORD),    // dwDesiredAccess
                PIN_PARG(DWORD),    // dwFileOffsetHigh
                PIN_PARG(DWORD),    // dwFileOffsetLow
                PIN_PARG(size_t),   // dwNumberOfBytesToMap
                PIN_PARG_END());

            RTN_ReplaceSignature(rtn, (AFUNPTR)MapViewOfFile_hook,
                IARG_PROTOTYPE, proto, IARG_ORIG_FUNCPTR, IARG_RETURN_IP, IARG_CONST_CONTEXT,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);

            PROTO_Free(proto);
        }

        // Hook beginning of UnMapViewOfFile
        rtn = RTN_FindByName(img, "UnmapViewOfFile");

        if (rtn != RTN_Invalid())
        {
            RTN_Open(rtn);
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)UnmapViewOfFile_before, IARG_REG_VALUE, REG_ESP, IARG_END);
            RTN_Close(rtn);
        }

        // Find GlobalLock and GlobalUnlock to access clipboard data
        if ((rtn = RTN_FindByName(img, "GlobalLock")) != RTN_Invalid())
            GlobalLock = RTN_Address(rtn);

        if ((rtn = RTN_FindByName(img, "GlobalUnlock")) != RTN_Invalid())
            GlobalUnlock = RTN_Address(rtn);
    }
    else if (string_endswith(img_name, "user32.dll"))
    {
        // Hook beginning of MessageBoxA
        // Used for HWID and anti-debug error search
        RTN rtn = RTN_FindByName(img, "MessageBoxExA");

        if (rtn != RTN_Invalid())
        {
            RTN_Open(rtn);
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MessageBoxExA_before, IARG_REG_VALUE, REG_ESP, IARG_END);
            RTN_Close(rtn);
        }

        // Hook beginning of SetClipboardData if HWID search is active
        if (!skip_hwid.Value())
        {
            rtn = RTN_FindByName(img, "SetClipboardData");

            if (rtn != RTN_Invalid())
            {
                RTN_Open(rtn);
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SetClipboardData_before, IARG_REG_VALUE, REG_ESP, IARG_CONTEXT, IARG_END);
                RTN_Close(rtn);
            }
        }
    }
}

// Instrument instructions
VOID insInstrumentation(INS ins, VOID* v)
{
    // In launch mode, we'd like to use PIN_Detach() to stop all instrumentation once we patch the RSA keys
    // Unfortunately, to do that PIN launches an external process that has to attach as a debugger and sets
    // off WL's anti-debug checks.  Bypassing those is not as simple as borrowing ScyllaHide's techniques
    // since we need to catch when it attaches (after we've lost instrumentation ability) to modify the PEB
    // 
    // It's doable, but a work in progress for now
    // 
    // In the meantime, instead of detaching, we just use PIN_RemoveInstrumentation() and the check here to avoid reinstrumenting
    // It's still slower than running natively, but that's where we're at right now
    if (!mgr.attached())
        return;

    ADDRINT addr = INS_Address(ins);

    // If we haven't found the license copy address yet
    if (lic_copy == 0)
    {
        // If the license file hasn't been memory mapped yet
        if (lic_mapped)
        {
            // After license file is mapped to memory, it will be copied bytewise to a new location
            // We will track one-byte writes while it is mapped then check those for the new buffer
            UINT32 memOperands = INS_MemoryOperandCount(ins);

            for (UINT32 memOp = 0; memOp < memOperands; memOp++)
                if ((INS_MemoryOperandSize(ins, memOp) == 1) &&
                    INS_MemoryOperandIsWritten(ins, memOp) &&
                    INS_IsValidForIpointAfter(ins))
                    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)record_license_copy,
                        IARG_MEMORYOP_EA, memOp, IARG_END);
        }
    }
    else
    {
        // Start instrumenting every instruction after initial license copy is found
        // These will get forwarded to the individual stages to handle in turn
        
        // Instrument reads and writes
        UINT32 memOperands = INS_MemoryOperandCount(ins);

        for (UINT32 memOp = 0; memOp < memOperands; memOp++)
        {
            const UINT32 size = INS_MemoryOperandSize(ins, memOp);

            if (INS_MemoryOperandIsRead(ins, memOp))
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) process_read,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_ADDRINT, size,
                    IARG_CONTEXT,
                    IARG_END);

            if (INS_MemoryOperandIsWritten(ins, memOp) && INS_IsValidForIpointAfter(ins))
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) process_write,
                    IARG_INST_PTR,
                    IARG_MEMORYOP_EA, memOp,
                    IARG_ADDRINT, size,
                    IARG_CONTEXT,
                    IARG_END);
        }

        // General instruction instrumentation
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) process_ins,
            IARG_INST_PTR,
            IARG_CONTEXT,
            IARG_END);
    }
}

// Runs when program exits
VOID finished(INT32 code, VOID* v)
{
    logfile << "\nFinished\n";
    logfile.close();
}

int main(int argc, char* argv[])
{
    // Init PIN
    PIN_InitSymbols();

    // Parse command line
    if (PIN_Init(argc, argv))
        return -1;

    // Open log file
    logfile.open(log_filename.Value().c_str());

    // Return if unable to open log file
    // There's no clean way to log errors up through this point
    // If you're not even getting a log file, make sure you're trying to put it somewhere writable
    if (!logfile)
        return -1;

    // Get target filename
    // You'd think they'd make this available as a KNOB string but here we are
    // PIN has already searched argv by this point to verify the target appears in the correct format
    // We never have to worry about this failing here and 'target' remaining a null pointer or overindexing argv
    char *target = 0;

    for (size_t i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--"))
        {
            target = argv[i + 1];
            break;
        }
        
    logfile << "wl-extract -- main_hash extraction tool\n";
    logfile << "Target:\t" << target << '\n';

    switch (lic.load(regkey_dat.Value(), regkey_rsa.Value()))
    {
    case LD_ERROR_BAD_LICENSE:
        logfile << "Unable to load license file: " << lic.nt_path << std::endl;
        return -1;
    case LD_ERROR_BAD_RSA:
        logfile << "Unable to load RSA file: " << regkey_rsa.Value() << std::endl;
        return -1;
    default:
        logfile << "License file:\t" << lic.nt_path << '\n';
        logfile << "RSA file:\t" << regkey_rsa.Value() << '\n' << std::endl;
    }

    lic.launch_mode = launch_mode.Value();

    if (lic.launch_mode)
        logfile << "Launch mode\n";

    // Skip collecting HWID in launch mode
    lic.skip_hwid = (lic.launch_mode) ? true : skip_hwid.Value();

    if (lic.skip_hwid)
        logfile << "Skipping HWID collection\n" << std::endl;

    // Setup PIN instrumentation callbacks
    IMG_AddInstrumentFunction(imgInstrumentation, 0);
    INS_AddInstrumentFunction(insInstrumentation, 0);
    PIN_AddFiniFunction(finished, 0);

    // Start analysis
    logfile << "Searching for license file memory mapping...\n" << std::endl;
    PIN_StartProgram();

    return 0;
}
