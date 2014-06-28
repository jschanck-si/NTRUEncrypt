/******************************************************************************
 * NTRU Cryptography Reference Source Code
 * Copyright (c) 2009-2013, by Security Innovation, Inc. All rights reserved. 
 *
 * ntru_crypto_ntru_poly.c is a component of ntru-crypto.
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
 
// Check windows
#if _WIN32 || _WIN64
   #if _WIN64
     #define ENV64BIT
  #else
    #define ENV32BIT
  #endif

// Check GCC
#elif __GNUC__
  #if __x86_64__ || __ppc64__
    #define ENV64BIT
  #else
    #define ENV32BIT
  #endif

#else
    #define ENVUNKNOWN
#endif

#ifdef TEST_COMPARE_CONVOLUTIONS
    #define ENV64BIT
    #define ENV32BIT
    #define ENVUNKNOWN
#endif /* def TEST_COMPARE_CONVOLUTIONS */

/******************************************************************************
 *
 * File: ntru_crypto_ntru_poly.c
 *
 * Contents: Routines for generating and operating on polynomials in the
 *           NTRU algorithm.
 *
 *****************************************************************************/

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"
#include "ntru_crypto_ntru_mgf1.h"


/* ntru_gen_poly
 *
 * Generates polynomials by creating for each polynomial, a list of the
 * indices of the +1 coefficients followed by a list of the indices of
 * the -1 coefficients.
 *
 * If a single polynomial is generated (non-product form), indices_counts
 * contains a single value of the total number of indices (for +1 and -1
 * comefficients combined).
 *
 * If multiple polynomials are generated (for product form), their lists of
 * indices are sequentially stored in the indices buffer.  Each byte of
 * indices_counts contains the total number of indices (for +1 and -1
 * coefficients combined) for a single polynomial, beginning with the
 * low-order byte for the first polynomial.  The high-order byte is unused.
 *
 * Returns NTRU_OK if successful.
 * Returns HASH_BAD_ALG if the algorithm is not supported.
 *
 */

uint32_t
ntru_gen_poly(
    NTRU_CRYPTO_HASH_ALGID  hash_algid,      /*  in - hash algorithm ID for
                                                      IGF-2 */
    uint8_t                 md_len,          /*  in - no. of octets in digest */
    uint8_t                 min_calls,       /*  in - minimum no. of hash
                                                      calls */
    uint16_t                seed_len,        /*  in - no. of octets in seed */
    uint8_t                *seed,            /*  in - pointer to seed */
    uint8_t                *buf,             /*  in - pointer to working
                                                      buffer */
    uint16_t                N,               /*  in - max index + 1 */
    uint8_t                 c_bits,          /*  in - no. bits for candidate */
    uint16_t                limit,           /*  in - conversion to index
                                                      limit */
    bool                    is_product_form, /*  in - if generating multiple
                                                      polys */
    uint32_t                indices_counts,  /*  in - nos. of indices needed */
    uint16_t               *indices)         /* out - address for indices */
{
    uint8_t  *mgf_out;
    uint8_t  *octets;
    uint8_t  *used;
    uint8_t   num_polys;
    uint16_t  num_indices;
    uint16_t  octets_available;
    uint16_t  index_cnt = 0;
    uint8_t   left = 0;
    uint8_t   num_left = 0;
    uint32_t  retcode;
    
    ASSERT(seed);
    ASSERT(buf);
    ASSERT(indices);

    /* generate minimum MGF1 output */

    mgf_out = buf + md_len + 4;
    if ((retcode = ntru_mgf1(buf, hash_algid, md_len, min_calls,
                             seed_len, seed, mgf_out)) != NTRU_OK)
    {
        return retcode;
    }
    
    octets = mgf_out;
    octets_available = min_calls * md_len;

    /* init indices counts for number of polynomials being generated */

    if (is_product_form)
    {
        /* number of indices for poly1 is in low byte of indices_counts,
         * number of indices for poly2 and poly3 are in next higher bytes
         */

        num_polys = 3;
        num_indices = (uint16_t)(indices_counts & 0xff);
        indices_counts >>= 8;

    }
    else
    {
        /* number of bytes for poly is in low 16 bits of indices_counts */

        num_polys = 1;
        num_indices = (uint16_t)indices_counts;
    }

    /* init used-index array */

    used = mgf_out + octets_available;
    memset(used, 0, N);

    /* generate indices (IGF-2) for all polynomials */

    while (num_polys > 0)
    {

        /* generate indices for a single polynomial */

        while (index_cnt < num_indices)
        {
            uint16_t index;
            uint8_t  num_needed;

            /* form next index to convert to an index */

            do {
                /* use any leftover bits first */

                if (num_left != 0)
                {
                    index = left << (c_bits - num_left);
                }
                else
                {
                    index = 0;
                }

                /* get the rest of the bits needed from new octets */

                num_needed = c_bits - num_left;
                while (num_needed != 0)
                {
                    /* get another octet */

                    if (octets_available == 0)
                    {
                        if ((retcode = ntru_mgf1(buf, hash_algid, md_len, 1,
                                                 0, NULL, mgf_out)) != NTRU_OK)
                        {
                            return retcode;
                        }
                        
                        octets = mgf_out;
                        octets_available = md_len;
                    }
                    left = *octets++;
                    --octets_available;

                    if (num_needed <= 8)
                    {
                        /* all bits needed to fill the index are in this octet */

                        index |= ((uint16_t)(left)) >> (8 - num_needed);
                        num_left = 8 - num_needed;
                        num_needed = 0;
                        left &= 0xff >> (8 - num_left);

                    }
                    else
                    {
                        /* another octet will be needed after using this
                         * whole octet
                         */

                        index |= ((uint16_t)left) << (num_needed - 8);
                        num_needed -= 8;
                    }
                }
            } while (index >= limit);

            /* form index and check if unique */

            index %= N;
            
            if (!used[index])
            {
                used[index] = 1;
                indices[index_cnt] = index;
                ++index_cnt;
            }
        }
        --num_polys;

        /* init for next polynomial if another polynomial to be generated */

        if (num_polys > 0)
        {
            memset(used, 0, N);
            num_indices = num_indices +
                          (uint16_t)(indices_counts & 0xff);
            indices_counts >>= 8;
        }
    }

    NTRU_RET(NTRU_OK);
}


/* ntru_poly_check_min_weight
 *
 * Checks that the number of 0, +1, and -1 trinary ring elements meet or exceed
 * a minimum weight.
 */

bool
ntru_poly_check_min_weight(
    uint16_t  num_els,              /*  in - degree of polynomial */
    uint8_t  *ringels,              /*  in - pointer to trinary ring elements */
    uint16_t  min_wt)               /*  in - minimum weight */
{
    uint16_t wt[3];
    uint16_t i;

    wt[0] = wt[1] = wt[2] = 0;
    
    for (i = 0; i < num_els; i++)
    {
       ++wt[ringels[i]];
    }
    
    if ((wt[0] < min_wt) || (wt[1] < min_wt) || (wt[2] < min_wt))
    {
        return FALSE;
    }
    
    return TRUE;
}

/* ntru_ring_mult_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is a sparse trinary polynomial with coefficients -1, 0,
 * and 1.  It is specified by a list, bi, of its nonzero indices containing
 * indices for the bi_P1_len +1 coefficients followed by the indices for the
 * bi_M1_len -1 coefficients.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * input array "b", or temp array "t".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

#ifdef ENV64BIT

void
ntru_ring_mult_indices_quadruple_width_conv(
    uint16_t const *a,          /*  in - pointer to ring element a */
    uint16_t        bi_P1_len,  /*  in - no. of +1 coefficients in b */
    uint16_t        bi_M1_len,  /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of N elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint32_t storage_width = 16;
    uint16_t mod_q_mask = q - 1;
    uint64_t full_mod_q_mask = (mod_q_mask << storage_width) | mod_q_mask;
    uint32_t mask_interval_tmp = ((1 << storage_width) / q);
    uint32_t mask_interval = mask_interval_tmp > 0 ? mask_interval_tmp : 1;
    uint16_t iA, iA64, iT, iB; /* Loop variables for the relevant arrays */
    uint16_t mask_time;
    const uint64_t *a64o0; /* expanded a */
    const uint64_t *a64o1; /* expanded a */
    const uint64_t *a64o2; /* expanded a */
    const uint64_t *a64o3; /* expanded a */
    uint64_t *t64o0; /* expanded t */
    uint64_t *t64o1; /* expanded t */
    uint64_t *t64o2; /* expanded t */
    uint64_t *t64o3; /* expanded t */
    uint16_t o0end, o1end, o2end, o3end;
    uint8_t picker;
    uint64_t *ptr;
    const uint64_t *cPtr;
    uint32_t iT64;
    uint16_t end;
    uint16_t Nmod4 = N & 3;

    /* ONLY WORKS FOR N ODD! */

    ASSERT(a);
    ASSERT(bi);
    ASSERT(t);
    ASSERT(c);

    a64o0 = (const uint64_t *) &a[0]; a64o1 = (const uint64_t *) &a[1];
    a64o2 = (const uint64_t *) &a[2]; a64o3 = (const uint64_t *) &a[3];
    t64o0 = (uint64_t *) &t[0]; t64o1 = (uint64_t *) &t[1]; 
    t64o2 = (uint64_t *) &t[2]; t64o3 = (uint64_t *) &t[3]; 
    o0end = N >> 2; o1end = (N-1) >> 2; o2end = (N-2) >> 2; o3end = (N-3) >> 2;
    full_mod_q_mask = (mod_q_mask << storage_width) | mod_q_mask;
    full_mod_q_mask = (full_mod_q_mask << 2*storage_width) | full_mod_q_mask;

    /* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */

    mask_time = 0;

    memset(t, 0, N *sizeof(uint16_t));
    for (iB = 0; iB < bi_M1_len; iB++) {
        iT = bi[iB + bi_P1_len];
        picker = iT & 3;

        /* first half -- from iT to N */
        switch (picker) {
            case 0: ptr = t64o0; end = o0end; break;
            case 1: ptr = t64o1; end = o1end; break;
            case 2: ptr = t64o2; end = o2end; break;
            case 3: ptr = t64o3; end = o3end; break;
        }

        iT64 = iT >> 2; iA64 = 0;

        for (; iT64 < end; iA64++, iT64++) {
            ptr[iT64] += a64o0[iA64];
        }
        iA = iA64 << 2; iT = (iT64 << 2) + picker;
        while (iT < N) {
            t[iT] += a[iA];
            iT++; iA++;
        }

        /* second half -- from 0 to start -1 */

        /* at this point we have used (N-bi[iB + bi_P1_len]) and iA should be
         * equal to bi[iB+bi_P1_len]+1.
         */
        iA64 = iA >> 2; iT64 = 0; 
        picker = iA & 3;
        switch (picker) {
            case 0: cPtr = a64o0; end = o0end; break;
            case 1: cPtr = a64o1; end = o1end; break;
            case 2: cPtr = a64o2; end = o2end; break;
            case 3: cPtr = a64o3; end = o3end; break;
        }

        for (; iA64 < end; iA64++, iT64++) {
            t64o0[iT64] += cPtr[iA64];
        }
        iT = iT64 << 2; iA = (iA64 << 2) + picker;
        while (iA < N) {
            t[iT] += a[iA];
            iT++; iA++;
        }

        mask_time++;
        if (mask_time == mask_interval) {
            t64o0[0] &= full_mod_q_mask;
            if (1 == Nmod4) {
                for (iT64 = 0; iT64 < o1end; iT64++) {
                    t64o1[iT64] &= full_mod_q_mask;
                }
            }

            else if (3 == Nmod4) {
                for (iT64 = 0; iT64 < o3end; iT64++) {
                    t64o3[iT64] &= full_mod_q_mask;
                }
            }
            else { ASSERT (0); }
            mask_time = 0;
        }
        
    } /* for (iB = 0; iB < bi_M1_len; iB++) -- minus-index loop */

    /* Minus everything */
    for (iT = 0; iT < N; iT++) {
        t[iT] = -t[iT]; t[iT] &= mod_q_mask;
    }
    mask_time = 0;

    for (iB = 0; iB < bi_P1_len; iB++) {
        iT = bi[iB];
        picker = iT & 3;

        /* first half -- from iT to N */
        switch (picker) {
            case 0: ptr = t64o0; end = o0end; break;
            case 1: ptr = t64o1; end = o1end; break;
            case 2: ptr = t64o2; end = o2end; break;
            case 3: ptr = t64o3; end = o3end; break;
        }

        iT64 = iT >> 2; iA64 = 0;

        for (; iT64 < end; iA64++, iT64++) {
            ptr[iT64] += a64o0[iA64];
        }
        iA = iA64 << 2; iT = (iT64 << 2) + picker;
        while (iT < N) {
            t[iT] += a[iA];
            iT++; iA++;
        }

        /* second half -- from 0 to start -1 */

        /* at this point we have used (N-bi[iB + bi_P1_len]) and iA should be
         * equal to bi[iB+bi_P1_len]+1. 
         */
        iA64 = iA >> 2; iT64 = 0; 
        picker = iA & 3;
        switch (picker) {
            case 0: cPtr = a64o0; end = o0end; break;
            case 1: cPtr = a64o1; end = o1end; break;
            case 2: cPtr = a64o2; end = o2end; break;
            case 3: cPtr = a64o3; end = o3end; break;
        }

        for (; iA64 < end; iA64++, iT64++) {
            t64o0[iT64] += cPtr[iA64];
        }
        iT = iT64 << 2; iA = (iA64 << 2) + picker;
        while (iA < N) {
            t[iT] += a[iA];
            iT++; iA++;
        }

        mask_time++;
        if (mask_time == mask_interval) {
            t64o0[0] &= full_mod_q_mask;
            if (1 == Nmod4) {
                for (iT64 = 0; iT64 < o1end; iT64++) {
                    t64o1[iT64] &= full_mod_q_mask;
                }
            }

            else if (3 == Nmod4) {
                for (iT64 = 0; iT64 < o3end; iT64++) {
                    t64o3[iT64] &= full_mod_q_mask;
                }
            }
            else { ASSERT (0); }
            mask_time = 0;
        }
        
    } /* for (iB = 0; iB < bi_P1_len; iB++) -- plus-index loop */

    /* c = (a * b) mod q */
    for (iT = 0; iT < N; iT++) {
        c[iT] = t[iT] & mod_q_mask;
    }

    return;
}

#endif  /* def ENV64BIT */



/* ntru_ring_mult_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is a sparse trinary polynomial with coefficients -1, 0,
 * and 1.  It is specified by a list, bi, of its nonzero indices containing
 * indices for the bi_P1_len +1 coefficients followed by the indices for the
 * bi_M1_len -1 coefficients.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * input array "b", or temp array "t".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

#ifdef ENV32BIT

void
ntru_ring_mult_indices_double_width_conv(
    uint16_t const *a,          /*  in - pointer to ring element a */
    uint16_t        bi_P1_len,  /*  in - no. of +1 coefficients in b */
    uint16_t        bi_M1_len,  /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of N elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint32_t storage_width = 16;
    uint16_t mod_q_mask = q - 1;
    uint32_t double_mod_q_mask = (mod_q_mask << storage_width) | mod_q_mask;
    uint32_t mask_interval_tmp = ((1 << storage_width) / q);
    uint32_t mask_interval = mask_interval_tmp > 0 ? mask_interval_tmp : 1;
    uint16_t iAE, iT, iB; /* Loop variables for the relevant arrays */
    uint16_t mask_time;
    const uint32_t *a32o0; /* expanded a */
    const uint32_t *a32o1; /* expanded a */
    uint32_t *t32o0; /* expanded t */
    uint32_t *t32o1; /* expanded t */

    /* ONLY WORKS FOR N ODD! */

    uint16_t halfN = (N-1)/2;

    ASSERT(a);
    ASSERT(bi);
    ASSERT(t);
    ASSERT(c);

    a32o0 = (const uint32_t *) &a[0]; a32o1 = (const uint32_t *) &a[1];
    t32o0 = (uint32_t *) &t[0]; t32o1 = (uint32_t *) &t[1]; 

    /* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */

    mask_time = 0;

    memset(t, 0, N *sizeof(uint16_t));
    for (iB = 0; iB < bi_M1_len; iB++) {
        iT = bi[iB + bi_P1_len];

        if (iT & 1) {
        /* Odd case -- use pointer to T1. Add a0 till iT1 = halfN. Then go back
         * to the start (iT0) and keep on adding a0 till we reach the end of
         * a0. Then add a[N-1] to the next t. */

            iT -= 1; iT /= 2;
            for (iAE = 0; iT < halfN && iAE < halfN; ++iAE, ++iT) {
                t32o1[iT] += a32o0[iAE];
            }
            iT = 0;
            for (; iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o0[iAE];
            }
            t[2*iT] += a[N-1];
        }

        else { /* iT & 1 == 0 */
        /* Even case -- add a0 till iT0 == halfN, at which point the a0 index =
         * say iA; then add the next entry of a to t[N-1]; and move the pointer
         * to iT = 0, i.e. t[0]; then add a1 from iA to the end. */
            iT /= 2;

            for (iAE = 0; iT < halfN && iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o0[iAE];
            }
            t[N-1] += a[iAE*2];
            iT = 0;
            for (; iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o1[iAE];
            }
        }

        mask_time++;
        if (mask_time == mask_interval) {
            t32o0[0] &= double_mod_q_mask;
            for (iT = 0; iT < halfN; iT++) {
                t32o1[iT] &= double_mod_q_mask;
            }
            mask_time = 0;
        }

    } /* for (iB = 0; iB < bi_M1_len; iB++) -- minus-index loop */

    /* Minus everything */
    for (iT = 0; iT < N; iT++) {
        t[iT] = -t[iT];
    }
    t32o0[0] &= double_mod_q_mask;
    for (iT = 0; iT < halfN; iT++) {
        t32o1[iT] &= double_mod_q_mask;
    }
    mask_time = 0;
    
    mask_time = 0;
    for (iB = 0; iB < bi_P1_len; iB++) {
        iT = bi[iB];
        if (iT & 1) {
        /* Odd case -- use pointer to T1. Add a0 till iT1 = halfN. Then go back
         * to the start (iT0) and keep on adding a0 till we reach the end of
         * a0. Then add a[N-1] to the next t. */

            iT -= 1; iT /= 2;
            for (iAE = 0; iT < halfN && iAE < halfN; ++iAE, ++iT) {
                t32o1[iT] += a32o0[iAE];
            }
            iT = 0;
            for (; iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o0[iAE];
            }
            t[2*iT] += a[N-1];
        }

        else { /* iT & 1 == 0 */
        /* Even case -- add a0 till iT0 == halfN, at which point the a0 index =
         * say iA; then add the next entry of a to t[N-1]; and move the pointer
         * to iT = 0, i.e. t[0]; then add a1 from iA to the end. */
            iT /= 2;

            for (iAE = 0; iT < halfN && iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o0[iAE];
            }
            t[N-1] += a[iAE*2];
            iT = 0;
            for (; iAE < halfN; ++iAE, ++iT) {
                t32o0[iT] += a32o1[iAE];
            }
        }

        mask_time++;
        if (mask_time == mask_interval) {
            t32o0[0] &= double_mod_q_mask;
            for (iT = 0; iT < halfN; iT++) {
                t32o1[iT] &= double_mod_q_mask;
            }
            mask_time = 0;
        }
    }

    /* c = (a * b) mod q */
    for (iT = 0; iT < N; iT++) {
        c[iT] = t[iT] & mod_q_mask;
    }

    return;
}
#endif  /* def ENV32BIT */


/* ntru_ring_mult_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is a sparse trinary polynomial with coefficients -1, 0,
 * and 1.  It is specified by a list, bi, of its nonzero indices containing
 * indices for the bi_P1_len +1 coefficients followed by the indices for the
 * bi_M1_len -1 coefficients.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * input array "b", or temp array "t".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */


#ifdef ENVUNKNOWN

void
ntru_ring_mult_indices_orig(
    uint16_t const *a,          /*  in - pointer to ring element a */
    uint16_t        bi_P1_len,  /*  in - no. of +1 coefficients in b */
    uint16_t        bi_M1_len,  /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of N elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t mod_q_mask = q - 1;
    uint16_t i, j, k;

    ASSERT(a);
    ASSERT(bi);
    ASSERT(t);
    ASSERT(c);

    /* t[(i+k)%N] = sum i=0 through N-1 of a[i], for b[k] = -1 */

    for (k = 0; k < N; k++)
    {
        t[k] = 0;
    }
    
    for (j = bi_P1_len; j < bi_P1_len + bi_M1_len; j++)
    {
        k = bi[j];
        
        for (i = 0; k < N; ++i, ++k)
        {
            t[k] = t[k] + a[i];
        }
        
        for (k = 0; i < N; ++i, ++k)
        {
            t[k] = t[k] + a[i];
        }
    }

    /* t[(i+k)%N] = -(sum i=0 through N-1 of a[i] for b[k] = -1) */

    for (k = 0; k < N; k++)
    {
        t[k] = -t[k];
    }
    
    /* t[(i+k)%N] += sum i=0 through N-1 of a[i] for b[k] = +1 */

    for (j = 0; j < bi_P1_len; j++)
    {
        k = bi[j];
        
        for (i = 0; k < N; ++i, ++k)
        {
            t[k] = t[k] + a[i];
        }
        
        for (k = 0; i < N; ++i, ++k)
        {
            t[k] = t[k] + a[i];
        }
    }

    /* c = (a * b) mod q */

    for (k = 0; k < N; k++)
    {
        c[k] = t[k] & mod_q_mask;
    }
    
    return;
}
#endif   /* def ENVUNKNOWN */

void
ntru_ring_mult_indices(
    uint16_t const *a,          /*  in - pointer to ring element a */
    uint16_t        bi_P1_len,  /*  in - no. of +1 coefficients in b */
    uint16_t        bi_M1_len,  /*  in - no. of -1 coefficients in b */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of ring element b,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of N elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
#ifdef ENV64BIT
    ntru_ring_mult_indices_quadruple_width_conv
        (a, bi_P1_len, bi_M1_len, bi, N, q, t, c);
    return;
#endif
#ifdef ENV32BIT
    ntru_ring_mult_indices_double_width_conv
        (a, bi_P1_len, bi_M1_len, bi, N, q, t, c);
    return;
#endif
#ifdef ENVUNKNOWN
    ntru_ring_mult_indices_orig (a, bi_P1_len, bi_M1_len, bi, N, q, t, c);
    return;
#endif
}



/* ntru_ring_mult_product_indices
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" is represented by the product form b1 * b2 + b3, where
 * b1, b2, and b3 are each a sparse trinary polynomial with coefficients -1,
 * 0, and 1.  It is specified by a list, bi, of the nonzero indices of b1, b2,
 * and b3, containing the indices for the +1 coefficients followed by the
 * indices for the -1 coefficients for each polynomial in that order.
 * The indices are in the range [0,N).
 *
 * The result array "c" may share the same memory space as input array "a",
 * or input array "b".
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

void
ntru_ring_mult_product_indices(
    uint16_t       *a,          /*  in - pointer to ring element a */
    uint16_t        b1i_len,    /*  in - no. of +1 or -1 coefficients in b1 */
    uint16_t        b2i_len,    /*  in - no. of +1 or -1 coefficients in b2 */
    uint16_t        b3i_len,    /*  in - no. of +1 or -1 coefficients in b3 */
    uint16_t const *bi,         /*  in - pointer to the list of nonzero
                                         indices of polynomials b1, b2, b3,
                                         containing indices for the +1
                                         coefficients followed by the
                                         indices for -1 coefficients for
                                         each polynomial */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of 2N elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t *t2 = t + N;
    uint16_t  mod_q_mask = q - 1;
    uint16_t  i;
    
    ASSERT(a);
    ASSERT(bi);
    ASSERT(t);
    ASSERT(c);

    /* t2 = a * b1 */

    ntru_ring_mult_indices(a, b1i_len, b1i_len, bi, N, q, t, t2);

    /* t2 = (a * b1) * b2 */

    ntru_ring_mult_indices(t2, b2i_len, b2i_len, bi + (b1i_len << 1), N, q,
                           t, t2);

    /* t = a * b3 */

    ntru_ring_mult_indices(a, b3i_len, b3i_len,
                           bi + ((b1i_len + b2i_len) << 1), N, q, t, t);

    /* c = (a * b1 * b2) + (a * b3) */

    for (i = 0; i < N; i++)
    {
        c[i] = (t2[i] + t[i]) & mod_q_mask;
    }
    
    return;
}


/* ntru_ring_mult_coefficients
 *
 * Multiplies ring element (polynomial) "a" by ring element (polynomial) "b"
 * to produce ring element (polynomial) "c" in (Z/qZ)[X]/(X^N - 1).
 * This is a convolution operation.
 *
 * Ring element "b" has coefficients in the range [0,N).
 *
 * This assumes q is 2^r where 8 < r < 16, so that overflow of the sum
 * beyond 16 bits does not matter.
 */

void
ntru_ring_mult_coefficients(
    uint16_t const *a,          /*  in - pointer to polynomial a */
    uint16_t const *b,          /*  in - pointer to polynomial b */
    uint16_t        N,          /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t const *bptr = b;
    uint16_t        mod_q_mask = q - 1;
    uint16_t        i, k;
    
    ASSERT(a);
    ASSERT(b);
    ASSERT(c);

    /* c[k] = sum(a[i] * b[k-i]) mod q */

    memset(c, 0, N * sizeof(uint16_t));
    
    for (k = 0; k < N; k++)
    {
        i = 0;
        while (i <= k)
        {
            c[k] += a[i++] * *bptr--;
        }
        
        bptr += N;
        
        while (i < N)
        {
            c[k] += a[i++] * *bptr--;
        }
        
        c[k] &= mod_q_mask;
        ++bptr;
    }
    
    return;
}


/* ntru_ring_inv
 *
 * Finds the inverse of a polynomial, a, in (Z/2^rZ)[X]/(X^N - 1).
 *
 * This assumes q is 2^r where 8 < r < 16, so that operations mod q can
 * wait until the end, and only 16-bit arrays need to be used.
 */

bool
ntru_ring_inv(
    uint16_t       *a,          /*  in - pointer to polynomial a */
    uint16_t        N,          /*  in - no. of coefficients in a */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *t,          /*  in - temp buffer of 2N elements */
    uint16_t       *a_inv)      /* out - address for polynomial a^-1 */
{
    uint8_t  *b = (uint8_t *)t;     /* b cannot be in a_inv since it must be
                                       rotated and copied there as a^-1 mod 2 */
    uint8_t  *c = b + N;            /* c cannot be in a_inv since it exchanges
                                       with b, and b cannot be in a_inv */
    uint8_t  *f = c + N;
    uint8_t  *g = (uint8_t *)a_inv; /* g needs N + 1 bytes */
    uint16_t *t2 = t + N;
    uint16_t  deg_b;
    uint16_t  deg_c;
    uint16_t  deg_f;
    uint16_t  deg_g;
    uint16_t  k = 0;
    uint16_t  i, j;

    if (a == NULL || t == NULL || a_inv == NULL || (q & (q-1)))
    {
        return FALSE;
    }

    /* form a^-1 in (Z/2Z)[X]/(X^N - 1) */

    memset(b, 0, (N << 1));         /* clear to init b, c */

    /* b(X) = 1 */

    b[0] = 1;
    deg_b = 0;

    /* c(X) = 0 (cleared above) */

    deg_c = 0;

    /* f(X) = a(X) mod 2 */

    deg_f = 0;
    for (i = 0; i < N; i++)
    {
        f[i] = (uint8_t)(a[i] & 1);
        if(f[i]) deg_f = i;
    }

    /* g(X) = X^N - 1 */

    g[0] = 1;
    memset(g + 1, 0, N - 1);
    g[N] = 1;
    deg_g = N;

    /* until f(X) = 1 */

    while (1)
    {
        /* while f[0] = 0, f(X) /= X, c(X) *= X, k++ */

        for (i = 0; (i <= deg_f) && (f[i] == 0); ++i);
        if (i > deg_f)
            return FALSE;
        if (i) {
            f = f + i;
            deg_f = deg_f - i;
            deg_c = deg_c + i;

            for (j = deg_c; j >= i; j--)
            {
                c[j] = c[j-i];
            }

            for (j = 0; j < i; j++)
            {
                c[j] = 0;
            }

            k = k + i;
        }

        /* if f(X) = 1, done */

        if (deg_f == 0)
        {
            break;
        }

        /* if deg_f < deg_g, f <-> g, b <-> c */

        if (deg_f < deg_g)
        {
            uint8_t *x;

            x = f;
            f = g;
            g = x;
            deg_f ^= deg_g;
            deg_g ^= deg_f;
            deg_f ^= deg_g;
            x = b;
            b = c;
            c = x;
            deg_b ^= deg_c;
            deg_c ^= deg_b;
            deg_b ^= deg_c;
        }

        /* f(X) += g(X)
         * might change degree of f if deg_g >= deg_f
         */

        for (i = 0; i <= deg_g; i++)
        {
            f[i] ^= g[i];
        }

        if(deg_g == deg_f)
        {
            while(deg_f > 0 && f[deg_f] == 0)
            {
                --deg_f;
            }
        }

        /* b(X) += c(X) */
        for (i = 0; i <= deg_c; i++)
        {
            b[i] ^= c[i];
        }

        if (deg_c >= deg_b)
        {
            deg_b = deg_c;
            while(deg_b > 0 && b[deg_b] == 0)
            {
                --deg_b;
            }
        }
    }

    /* a^-1 in (Z/2Z)[X]/(X^N - 1) = b(X) shifted left k coefficients */

    j = 0;

    if (k >= N)
    {
        k = k - N;
    }

    for (i = k; i < N; i++)
    {
        a_inv[j++] = (uint16_t)(b[i]);
    }

    for (i = 0; i < k; i++)
    {
        a_inv[j++] = (uint16_t)(b[i]);
    }

    /* lift a^-1 in (Z/2Z)[X]/(X^N - 1) to a^-1 in (Z/qZ)[X]/(X^N -1) */

    for (j = 0; j < 4; ++j)   /* assumes 256 < q <= 65536 */
    {

        /* a^-1 = a^-1 * (2 - a * a^-1) mod q */

        memcpy(t2, a_inv, N * sizeof(uint16_t));
        ntru_ring_mult_coefficients(a, t2, N, q, t);

        for (i = 0; i < N; ++i)
        {
            t[i] = q - t[i];
        }

        t[0] = t[0] + 2;
        ntru_ring_mult_coefficients(t2, t, N, q, a_inv);
    }

    return TRUE;

}


#ifdef ENV64BIT
    #undef ENV64BIT
#endif
#ifdef ENV32BIT
    #undef ENV32BIT
#endif
#ifdef ENVUNKNOWN
    #undef ENVUNKNOWN
#endif
