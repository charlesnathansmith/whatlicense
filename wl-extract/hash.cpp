/********************************************************************************
*
* WhatLicense
* Nathan Smith
* https://github.com/charlesnathansmith/whatlicense
*
*  wl-extract
*  main_hash extraction tool
*   Main hash building functions
*
*  Functions to convert the extracted keys and hashes back into
*  a valid main_hash alphanumeric string
*
********************************************************************************/

#include <cstdint>
#include "hash.h"

// Finds two alphanumeric strings a and b that could sum together to a given value
// Returns false if invalid input provided (individual sum bytes should be between 0x60 and 0xf4)
// Just uses a lookup table since a and b aren't subject to any other constraints
bool solve_alphanum_sum(uint8_t* a, uint8_t* b, const uint8_t* sum, size_t size)
{
    static const uint16_t lookup[] =
    {
        0x3030, /*60 -- 0, 0*/  0x3130, /*61 -- 1, 0*/  0x3230, /*62 -- 2, 0*/  0x3330, /*63 -- 3, 0*/  0x3430, /*64 -- 4, 0*/  0x3530, /*65 -- 5, 0*/
        0x3630, /*66 -- 6, 0*/  0x3730, /*67 -- 7, 0*/  0x3830, /*68 -- 8, 0*/  0x3930, /*69 -- 9, 0*/  0x3931, /*6a -- 9, 1*/  0x3932, /*6b -- 9, 2*/
        0x3933, /*6c -- 9, 3*/  0x3934, /*6d -- 9, 4*/  0x3935, /*6e -- 9, 5*/  0x3936, /*6f -- 9, 6*/  0x3937, /*70 -- 9, 7*/  0x4130, /*71 -- A, 0*/
        0x4230, /*72 -- B, 0*/  0x4330, /*73 -- C, 0*/  0x4430, /*74 -- D, 0*/  0x4530, /*75 -- E, 0*/  0x4630, /*76 -- F, 0*/  0x4730, /*77 -- G, 0*/
        0x4830, /*78 -- H, 0*/  0x4930, /*79 -- I, 0*/  0x4a30, /*7a -- J, 0*/  0x4b30, /*7b -- K, 0*/  0x4c30, /*7c -- L, 0*/  0x4d30, /*7d -- M, 0*/
        0x4e30, /*7e -- N, 0*/  0x4f30, /*7f -- O, 0*/  0x5030, /*80 -- P, 0*/  0x5130, /*81 -- Q, 0*/  0x5230, /*82 -- R, 0*/  0x5330, /*83 -- S, 0*/
        0x5430, /*84 -- T, 0*/  0x5530, /*85 -- U, 0*/  0x5630, /*86 -- V, 0*/  0x5730, /*87 -- W, 0*/  0x5830, /*88 -- X, 0*/  0x5930, /*89 -- Y, 0*/
        0x5a30, /*8a -- Z, 0*/  0x5a31, /*8b -- Z, 1*/  0x5a32, /*8c -- Z, 2*/  0x5a33, /*8d -- Z, 3*/  0x5a34, /*8e -- Z, 4*/  0x5a35, /*8f -- Z, 5*/
        0x5a36, /*90 -- Z, 6*/  0x5a37, /*91 -- Z, 7*/  0x5a38, /*92 -- Z, 8*/  0x5a39, /*93 -- Z, 9*/  0x5341, /*94 -- S, A*/  0x5441, /*95 -- T, A*/
        0x5541, /*96 -- U, A*/  0x5641, /*97 -- V, A*/  0x5741, /*98 -- W, A*/  0x5841, /*99 -- X, A*/  0x5941, /*9a -- Y, A*/  0x5a41, /*9b -- Z, A*/
        0x5a42, /*9c -- Z, B*/  0x5a43, /*9d -- Z, C*/  0x5a44, /*9e -- Z, D*/  0x5a45, /*9f -- Z, E*/  0x5a46, /*a0 -- Z, F*/  0x5a47, /*a1 -- Z, G*/
        0x5a48, /*a2 -- Z, H*/  0x5a49, /*a3 -- Z, I*/  0x5a4a, /*a4 -- Z, J*/  0x5a4b, /*a5 -- Z, K*/  0x5a4c, /*a6 -- Z, L*/  0x5a4d, /*a7 -- Z, M*/
        0x5a4e, /*a8 -- Z, N*/  0x5a4f, /*a9 -- Z, O*/  0x5a50, /*aa -- Z, P*/  0x5a51, /*ab -- Z, Q*/  0x5a52, /*ac -- Z, R*/  0x5a53, /*ad -- Z, S*/
        0x5a54, /*ae -- Z, T*/  0x5a55, /*af -- Z, U*/  0x5a56, /*b0 -- Z, V*/  0x5a57, /*b1 -- Z, W*/  0x5a58, /*b2 -- Z, X*/  0x5a59, /*b3 -- Z, Y*/
        0x5a5a, /*b4 -- Z, Z*/  0x5461, /*b5 -- T, a*/  0x5561, /*b6 -- U, a*/  0x5661, /*b7 -- V, a*/  0x5761, /*b8 -- W, a*/  0x5861, /*b9 -- X, a*/
        0x5961, /*ba -- Y, a*/  0x5a61, /*bb -- Z, a*/  0x5a62, /*bc -- Z, b*/  0x5a63, /*bd -- Z, c*/  0x5a64, /*be -- Z, d*/  0x5a65, /*bf -- Z, e*/
        0x5a66, /*c0 -- Z, f*/  0x5a67, /*c1 -- Z, g*/  0x5a68, /*c2 -- Z, h*/  0x5a69, /*c3 -- Z, i*/  0x5a6a, /*c4 -- Z, j*/  0x5a6b, /*c5 -- Z, k*/
        0x5a6c, /*c6 -- Z, l*/  0x5a6d, /*c7 -- Z, m*/  0x5a6e, /*c8 -- Z, n*/  0x5a6f, /*c9 -- Z, o*/  0x5a70, /*ca -- Z, p*/  0x5a71, /*cb -- Z, q*/
        0x5a72, /*cc -- Z, r*/  0x5a73, /*cd -- Z, s*/  0x5a74, /*ce -- Z, t*/  0x5a75, /*cf -- Z, u*/  0x5a76, /*d0 -- Z, v*/  0x5a77, /*d1 -- Z, w*/
        0x5a78, /*d2 -- Z, x*/  0x5a79, /*d3 -- Z, y*/  0x5a7a, /*d4 -- Z, z*/  0x7461, /*d5 -- t, a*/  0x7561, /*d6 -- u, a*/  0x7661, /*d7 -- v, a*/
        0x7761, /*d8 -- w, a*/  0x7861, /*d9 -- x, a*/  0x7961, /*da -- y, a*/  0x7a61, /*db -- z, a*/  0x7a62, /*dc -- z, b*/  0x7a63, /*dd -- z, c*/
        0x7a64, /*de -- z, d*/  0x7a65, /*df -- z, e*/  0x7a66, /*e0 -- z, f*/  0x7a67, /*e1 -- z, g*/  0x7a68, /*e2 -- z, h*/  0x7a69, /*e3 -- z, i*/
        0x7a6a, /*e4 -- z, j*/  0x7a6b, /*e5 -- z, k*/  0x7a6c, /*e6 -- z, l*/  0x7a6d, /*e7 -- z, m*/  0x7a6e, /*e8 -- z, n*/  0x7a6f, /*e9 -- z, o*/
        0x7a70, /*ea -- z, p*/  0x7a71, /*eb -- z, q*/  0x7a72, /*ec -- z, r*/  0x7a73, /*ed -- z, s*/  0x7a74, /*ee -- z, t*/  0x7a75, /*ef -- z, u*/
        0x7a76, /*f0 -- z, v*/  0x7a77, /*f1 -- z, w*/  0x7a78, /*f2 -- z, x*/  0x7a79, /*f3 -- z, y*/  0x7a7a  /*f4 -- z, z*/
    };

    if (!a || !b || !sum)
        return false;

    // Solve one byte at a time
    for (size_t i = 0; i < size; i++)
    {
        if ((sum[i] < 0x60) || (sum[i] > 0xf4))
            return false; //invalid sum value

        uint16_t pair = lookup[sum[i] - 0x60]; // 0x60 is lowest possible byte sum, start of table

        a[i] = pair >> 8;
        b[i] = pair & 0xff;
    }

    return true;
}

// solve_alphanum_sum for 32-bit sum
bool solve_alphanum_sum32(uint32_t* a, uint32_t* b, uint32_t sum)
{
    return solve_alphanum_sum((uint8_t*) a, (uint8_t*) b, (uint8_t*) &sum, 4);
}

// solve_alphanum_sum for 16-bit sum
bool solve_alphanum_sum16(uint16_t* a, uint16_t* b, uint16_t sum)
{
    return solve_alphanum_sum((uint8_t*) a, (uint8_t*) b, (uint8_t*) &sum, 2);
}