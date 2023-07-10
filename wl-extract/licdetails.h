/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   License detail management
*
* Manages information about the license file we're using
*
********************************************************************************/

#pragma once
#include <cstdint>
#include <string>
#include <fstream>
#include "rsakey.h"

constexpr int LD_ERROR_BAD_LICENSE = 1;
constexpr int LD_ERROR_BAD_RSA = 2;

struct lic_details
{
	std::string nt_path;					// License absolute file path "\\??\\C:\\ ..."
	std::string head;						// First 8 bytes of license file - needed to locate intial mapping
	size_t size;							// Size of license file

	rsa_public_key rsa_key_1, rsa_key_2;	// RSA public keys
	
	// These should probably be moved to stage_mgr
	bool launch_mode;						// Running in launch mode
	bool skip_hwid;							// Skip HWID search and exit early

	// Load license and RSA file data
	int load(const std::string& lic_path, const std::string& key_path);
};
