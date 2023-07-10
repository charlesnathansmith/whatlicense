/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   NT structures
*
* NT structures we need for redirecting NtCreateFile to our license file
* Importing Windows.h will clash with the PIN CRT, and we don't need most of it
*
********************************************************************************/

#pragma once
#include <cstdint>

#define HANDLE void*
#define DWORD unsigned long

struct UNICODE_STRING {
    uint16_t    Length;
    uint16_t    MaximumLength;
    wchar_t*    Buffer;
};

struct OBJECT_ATTRIBUTES {
    unsigned long   Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    unsigned long   Attributes;
    void*           SecurityDescriptor;
    void*           SecurityQualityOfService;
};
