/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Miscellaneous Utilities
*
********************************************************************************/

#include <string>
#include "utils.h"

// Find potential HWID in a string
bool find_hwid(const char* text, char* out)
{
    // HWID test buffer
    char hwid[40];
    hwid[39] = '\0';

    while (char* start = strchr(text, '-'))
    {
        if (PIN_SafeCopy(hwid, start - 4, 39) != 39)
            return false;

        bool good = true;

        for (char* pos = hwid + 9; pos < hwid + 39; pos += 5)
            if (*pos != '-')
            {
                good = false;
                break;
            }

        if (good)
        {
            strncpy(out, hwid, 40);
            return true;
        }
    }

    return false;
}

// Returns true if str ends with substr
// Case insensitive -- used for finding modules from full paths
bool string_endswith(const std::string& str, const std::string& substr)
{
	if (str.size() < substr.size())
		return false;
	else
		return !_stricmp(str.end() - substr.size(), substr.c_str());
}
