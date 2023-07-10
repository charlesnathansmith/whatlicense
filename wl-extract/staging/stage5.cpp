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

#include <cstdint>
#include <fstream>
#include "pin.H"
#include "../utils.h"
#include "../hash.h"
#include "stage5.h"

// Start Stage
void stage5::init(ADDRINT input)
{
	logfile << "Stage 5 -- Generate main_hash\n\n";

    main_hash_bin bin;

    // Fill in unused values
    // This includes terms used to calculate hash_1 and hash_2, and hwid_key,
    // since these are never actually verified
    memset(&bin.unused_1[0], 'a', (size_t)&bin.hash_3_[0] - (size_t)&bin.unused_1[0]);
    memset(&bin.unused_2[0], 'a', 8);
    memset(&bin.hwid_key, 'a', 4);

    // Fill in terms that sum to hash_3
    if (!solve_alphanum_sum16(&bin.hash_3_[0], &bin.hash_3_[1], hash.hash_3))
    {
        logfile << "Cannot generate main_hash: hash_3 invalid" << std::endl;
    }
    else
    {
        // Fill in terms that sum to TEA key
        for (size_t i = 0; i < 4; i++)
            if (!solve_alphanum_sum32(&bin.tea_key_1_[i], &bin.tea_key_2_[i], hash.tea_key[i]))
            {
                logfile << "Cannot generate main_hash: TEA key invalid" << std::endl;
                PIN_ExitApplication(-1);
            }

        // Fill in password
        memcpy(bin.password, hash.password.c_str(), 32);

        logfile << "main_hash (not unique): " << bin.c_str() << std::endl;
    }

    if (lic_det.skip_hwid && !lic_det.launch_mode)
        PIN_ExitApplication(0);
}
