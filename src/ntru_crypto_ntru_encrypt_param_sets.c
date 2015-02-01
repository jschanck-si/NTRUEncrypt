/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_param_sets.c is a component of ntru-crypto.
 *
 * Copyright (C) 2009-2013  Security Innovation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/
 
/******************************************************************************
 *
 * File: ntru_crypto_ntru_encrypt_param_sets.c
 *
 * Contents: Defines the NTRUEncrypt parameter sets.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"


/* parameter sets */

static NTRU_ENCRYPT_PARAM_SET ntruParamSets[] = {

    {
        CHL_63R0,                    /* parameter-set id */
        "chl-63r0",                  /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        6,                           /* no. of bits in N (i.e., in an index) */
        63,                          /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        512,                         /* q */
        9,                           /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        3 + (3 << 8) + (3 << 16),    /* df, dr */
        21,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        10,                          /* dm0 */
        252,                         /* 2^c - (2^c mod N) */
        8,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_107R0,                   /* parameter-set id */
        "chl-107r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        7,                           /* no. of bits in N (i.e., in an index) */
        107,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        512,                         /* q */
        9,                           /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        4 + (4 << 8) + (4 << 16),    /* df, dr */
        36,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        20,                          /* dm0 */
        2033,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_113R0,                   /* parameter-set id */
        "chl-113r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        7,                           /* no. of bits in N (i.e., in an index) */
        113,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        5 + (4 << 8) + (3 << 16),    /* df, dr */
        38,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        22,                          /* dm0 */
        1017,                        /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_131R0,                   /* parameter-set id */
        "chl-131r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        131,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        5 + (4 << 8) + (4 << 16),    /* df, dr */
        44,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        27,                          /* dm0 */
        4061,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_139R0,                   /* parameter-set id */
        "chl-139r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        139,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        5 + (5 << 8) + (3 << 16),    /* df, dr */
        46,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        29,                          /* dm0 */
        973,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_149R0,                   /* parameter-set id */
        "chl-149r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        149,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        5 + (5 << 8) + (3 << 16),    /* df, dr */
        50,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        31,                          /* dm0 */
        447,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_163R0,                   /* parameter-set id */
        "chl-163r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        163,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        5 + (5 << 8) + (4 << 16),    /* df, dr */
        54,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        35,                          /* dm0 */
        4075,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_173R0,                   /* parameter-set id */
        "chl-173r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        173,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (5 << 8) + (4 << 16),    /* df, dr */
        58,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        38,                          /* dm0 */
        8131,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_181R0,                   /* parameter-set id */
        "chl-181r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        181,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (5 << 8) + (4 << 16),    /* df, dr */
        60,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        40,                          /* dm0 */
        8145,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_191R0,                   /* parameter-set id */
        "chl-191r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        191,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (5 << 8) + (4 << 16),    /* df, dr */
        64,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        43,                          /* dm0 */
        191,                         /* 2^c - (2^c mod N) */
        8,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_199R0,                   /* parameter-set id */
        "chl-199r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        199,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (5 << 8) + (6 << 16),    /* df, dr */
        66,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        45,                          /* dm0 */
        995,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_211R0,                   /* parameter-set id */
        "chl-211r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        211,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (6 << 8) + (4 << 16),    /* df, dr */
        70,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        48,                          /* dm0 */
        211,                         /* 2^c - (2^c mod N) */
        8,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_227R0,                   /* parameter-set id */
        "chl-227r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        227,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        6 + (6 << 8) + (4 << 16),    /* df, dr */
        76,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        53,                          /* dm0 */
        2043,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_239R0,                   /* parameter-set id */
        "chl-239r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        239,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (6 << 8) + (4 << 16),    /* df, dr */
        80,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        56,                          /* dm0 */
        239,                         /* 2^c - (2^c mod N) */
        8,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_251R0,                   /* parameter-set id */
        "chl-251r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        8,                           /* no. of bits in N (i.e., in an index) */
        251,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (6 << 8) + (4 << 16),    /* df, dr */
        84,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        59,                          /* dm0 */
        251,                         /* 2^c - (2^c mod N) */
        8,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_263R0,                   /* parameter-set id */
        "chl-263r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        263,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (6 << 8) + (4 << 16),    /* df, dr */
        88,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        63,                          /* dm0 */
        8153,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_271R0,                   /* parameter-set id */
        "chl-271r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        271,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        1024,                        /* q */
        10,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (6 << 8) + (6 << 16),    /* df, dr */
        90,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        65,                          /* dm0 */
        4065,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_281R0,                   /* parameter-set id */
        "chl-281r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        281,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (7 << 8) + (4 << 16),    /* df, dr */
        94,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        68,                          /* dm0 */
        8149,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_293R0,                   /* parameter-set id */
        "chl-293r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        293,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (7 << 8) + (4 << 16),    /* df, dr */
        98,                          /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        71,                          /* dm0 */
        879,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_307R0,                   /* parameter-set id */
        "chl-307r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        307,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        7 + (7 << 8) + (4 << 16),    /* df, dr */
        102,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        75,                          /* dm0 */
        921,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_317R0,                   /* parameter-set id */
        "chl-317r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        317,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (7 << 8) + (5 << 16),    /* df, dr */
        106,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        78,                          /* dm0 */
        951,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_331R0,                   /* parameter-set id */
        "chl-331r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        331,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (7 << 8) + (5 << 16),    /* df, dr */
        110,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        82,                          /* dm0 */
        993,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_347R0,                   /* parameter-set id */
        "chl-347r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        347,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (7 << 8) + (5 << 16),    /* df, dr */
        116,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        87,                          /* dm0 */
        347,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_359R0,                   /* parameter-set id */
        "chl-359r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        359,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (7 << 8) + (8 << 16),    /* df, dr */
        120,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        90,                          /* dm0 */
        3949,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_367R0,                   /* parameter-set id */
        "chl-367r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        367,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (5 << 16),    /* df, dr */
        122,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        92,                          /* dm0 */
        4037,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_379R0,                   /* parameter-set id */
        "chl-379r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        379,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (5 << 16),    /* df, dr */
        126,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        96,                          /* dm0 */
        379,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_389R0,                   /* parameter-set id */
        "chl-389r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        389,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (5 << 16),    /* df, dr */
        130,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        99,                          /* dm0 */
        8169,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        CHL_401R0,                   /* parameter-set id */
        "chl-401r0",                 /* human readable param set name */
        {0xFF, 0xFF, 0xFF},          /* OID */
        0xFF,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        32,                          /* (fake sec_strength, force SHA256 in keygen) */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (6 << 16),    /* df, dr */
        134,                         /* dg */
        0,                           /* maxMsgLenBytes - 0 to prevent use for encryption */
        103,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        0,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },









    {
        NTRU_EES401EP1,              /* parameter-set id */
        "ees401ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x04},          /* OID */
        0x22,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        113,                         /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        113,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        32,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES449EP1,              /* parameter-set id */
        "ees449ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x03},          /* OID */
        0x23,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        449,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        134,                         /* df, dr */
        149,                         /* dg */
        67,                          /* maxMsgLenBytes */
        134,                         /* dm0 */
        449,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        31,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES677EP1,              /* parameter-set id */
        "ees677ep1",                 /* human readable param set name */
        {0x00, 0x05, 0x03},          /* OID */
        0x24,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        677,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        157,                         /* df, dr */
        225,                         /* dg */
        101,                         /* maxMsgLenBytes */
        157,                         /* dm0 */
        2031,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        27,                          /* min. no. of hash calls for IGF-2 */
        9,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1087EP2,             /* parameter-set id */
        "ees1087ep2",                /* human readable param set name */
        {0x00, 0x06, 0x03},          /* OID */
        0x25,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1087,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        120,                         /* df, dr */
        362,                         /* dg */
        170,                         /* maxMsgLenBytes */
        120,                         /* dm0 */
        7609,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        25,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES541EP1,              /* parameter-set id */
        "ees541ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x05},          /* OID */
        0x26,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        541,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        49,                          /* df, dr */
        180,                         /* dg */
        86,                          /* maxMsgLenBytes */
        49,                          /* dm0 */
        3787,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        15,                          /* min. no. of hash calls for IGF-2 */
        11,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES613EP1,              /* parameter-set id */
        "ees613ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x04},          /* OID */
        0x27,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        613,                         /* N */
        16,                          /* securuity strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        55,                          /* df, dr */
        204,                         /* dg */
        97,                          /* maxMsgLenBytes */
        55,                          /* dm0 */
        1839,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        16,                          /* min. no. of hash calls for IGF-2 */
        13,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES887EP1,              /* parameter-set id */
        "ees887ep1",                 /* human readable param set name */
        {0x00, 0x05, 0x04},          /* OID */
        0x28,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        887,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        81,                          /* df, dr */
        295,                         /* dg */
        141,                         /* maxMsgLenBytes */
        81,                          /* dm0 */
        887,                         /* 2^c - (2^c mod N) */
        10,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        12,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1171EP1,             /* parameter-set id */
        "ees1171ep1",                /* human readable param set name */
        {0x00, 0x06, 0x04},          /* OID */
        0x29,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1171,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        106,                         /* df, dr */
        390,                         /* dg */
        186,                         /* maxMsgLenBytes */
        106,                         /* dm0 */
        3513,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        20,                          /* min. no. of hash calls for IGF-2 */
        15,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES659EP1,              /* parameter-set id */
        "ees659ep1",                 /* human readable param set name */
        {0x00, 0x02, 0x06},          /* OID */
        0x2a,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        659,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        38,                          /* df, dr */
        219,                         /* dg */
        108,                         /* maxMsgLenBytes */
        38,                          /* dm0 */
        1977,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        11,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES761EP1,              /* parameter-set id */
        "ees761ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x05},          /* OID */
        0x2b,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        761,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        42,                          /* df, dr */
        253,                         /* dg */
        125,                         /* maxMsgLenBytes */
        42,                          /* dm0 */
        3805,                        /* 2^c - (2^c mod N) */
        12,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        16,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1087EP1,             /* parameter-set id */
        "ees1087ep1",                /* human readable param set name */
        {0x00, 0x05, 0x05},          /* OID */
        0x2c,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1087,                        /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        63,                          /* df, dr */
        362,                         /* dg */
        178,                         /* maxMsgLenBytes */
        63,                          /* dm0 */
        7609,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        13,                          /* min. no. of hash calls for IGF-2 */
        14,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES1499EP1,             /* parameter-set id */
        "ees1499ep1",                /* human readable param set name */
        {0x00, 0x06, 0x05},          /* OID */
        0x2d,                        /* DER id */
        11,                          /* no. of bits in N (i.e., in an index) */
        1499,                        /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        FALSE,                       /* product form */
        79,                          /* df, dr */
        499,                         /* dg */
        247,                         /* maxMsgLenBytes */
        79,                          /* dm0 */
        7495,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        17,                          /* min. no. of hash calls for IGF-2 */
        19,                          /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES401EP2,              /* parameter-set id */
        "ees401ep2",                 /* human readable param set name */
        {0x00, 0x02, 0x10},          /* OID */
        0x2e,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        401,                         /* N */
        14,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        8 + (8 << 8) + (6 << 16),    /* df, dr */
        133,                         /* dg */
        60,                          /* maxMsgLenBytes */
        101,                         /* dm0 */
        2005,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        10,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES439EP1,              /* parameter-set id */
        "ees439ep1",                 /* human readable param set name */
        {0x00, 0x03, 0x10},          /* OID */
        0x2f,                        /* DER id */
        9,                           /* no. of bits in N (i.e., in an index) */
        439,                         /* N */
        16,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        9 + (8 << 8) + (5 << 16),    /* df, dr */
        146,                         /* dg */
        65,                          /* maxMsgLenBytes */
        112,                         /* dm0 */
        439,                         /* 2^c - (2^c mod N) */
        9,                           /* c */
        1,                           /* lLen */
        15,                          /* min. no. of hash calls for IGF-2 */
        6,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES593EP1,              /* parameter-set id */
        "ees593ep1",                 /* human readable param set name */
        {0x00, 0x05, 0x10},          /* OID */
        0x30,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        593,                         /* N */
        24,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        10 + (10 << 8) + (8 << 16),  /* df, dr */
        197,                         /* dg */
        86,                          /* maxMsgLenBytes */
        158,                         /* dm0 */
        1779,                        /* 2^c - (2^c mod N) */
        11,                          /* c */
        1,                           /* lLen */
        12,                          /* min. no. of hash calls for IGF-2 */
        5,                           /* min. no. of hash calls for MGF-TP-1 */
    },

    {
        NTRU_EES743EP1,              /* parameter-set id */
        "ees743ep1",                 /* human readable param set name */
        {0x00, 0x06, 0x10},          /* OID */
        0x31,                        /* DER id */
        10,                          /* no. of bits in N (i.e., in an index) */
        743,                         /* N */
        32,                          /* security strength in octets */
        2048,                        /* q */
        11,                          /* no. of bits in q (i.e., in a coeff) */
        TRUE,                        /* product form */
        11 + (11 << 8) + (15 << 16), /* df, dr */
        247,                         /* dg */
        106,                         /* maxMsgLenBytes */
        204,                         /* dm0 */
        8173,                        /* 2^c - (2^c mod N) */
        13,                          /* c */
        1,                           /* lLen */
        12,                          /* min. no. of hash calls for IGF-2 */
        7,                           /* min. no. of hash calls for MGF-TP-1 */
    },

};

static size_t numParamSets =
                sizeof(ntruParamSets)/sizeof(NTRU_ENCRYPT_PARAM_SET);


/* functions */

/* ntru_encrypt_get_params_with_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id)   /*  in - parameter-set id */
{
    size_t i;

    for (i = 0; i < numParamSets; i++)
    {
        if (ntruParamSets[i].id == id)
        {
            return &(ntruParamSets[i]);
        }
    }
    
    return NULL;
}


/* ntru_encrypt_get_params_with_OID
 *
 * Looks up a set of NTRUEncrypt parameters based on the OID of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_OID(
    uint8_t const *oid)             /*  in - pointer to parameter-set OID */
{
    size_t i;

    for (i = 0; i < numParamSets; i++)
    {
        if (!memcmp(ntruParamSets[i].OID, oid, 3))
        {
            return &(ntruParamSets[i]);
        }
    }
    
    return NULL;
}


/* ntru_encrypt_get_params_with_DER_id
 *
 * Looks up a set of NTRUEncrypt parameters based on the DER id of the
 * parameter set.
 *
 * Returns a pointer to the parameter set parameters if successful.
 * Returns NULL if the parameter set cannot be found.
 */

NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_DER_id(
    uint8_t der_id)                 /*  in - parameter-set DER id */
{
    size_t i;

    for (i = 0; i < numParamSets; i++)
    {
        if (ntruParamSets[i].der_id == der_id)
        {
            return &(ntruParamSets[i]);
        }
    }
    return NULL;
}


const char*
ntru_encrypt_get_param_set_name(
    NTRU_ENCRYPT_PARAM_SET_ID id)   /*  in - parameter-set id */
{
    size_t i;

    for (i = 0; i < numParamSets; i++)
    {
        if (ntruParamSets[i].id == id)
        {
            return ntruParamSets[i].name;
        }
    }

    return NULL;
}
