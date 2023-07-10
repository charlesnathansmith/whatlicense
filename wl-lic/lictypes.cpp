/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-lic
*  License generation tool
*   License-building structures
*
********************************************************************************/

#include <cstdint>
#include "lictypes.h"

// Capitalize ascii HWID and check for invalid chars
bool reg_info::sanitize_hwid()
{
    for (char& c : hwid)
    {
        if ((c >= 'a') && (c <= 'f'))
        {
            c -= 0x20;      // Capitalize
            continue;
        }
        else if ((c != '-') && ((c < '0') || (c > '9')) && ((c < 'A') || (c > 'F')))
        {
            hwid.clear();   // Invalid char found
            return false;
        }
    }

    return true;
}