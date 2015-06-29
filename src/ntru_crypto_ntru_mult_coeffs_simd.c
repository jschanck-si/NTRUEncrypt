#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"
#include <immintrin.h>

static void
grade_school_mul(
    uint16_t        *res1,   /* out - a * b in Z[x], must be length 2N */
    uint16_t        *tmp1,   /*  in - N coefficients of scratch space */
    uint16_t const  *a,     /*  in - polynomial */
    uint16_t const  *b,     /*  in - polynomial */
    uint16_t const   N)     /*  in - number of coefficients in a and b */
{
  uint16_t const padN = (N + 0x0007) & 0xfff8;
  __m128i *T = alloca(2*padN*sizeof(uint16_t));
  memset(T,0,2*padN*sizeof(uint16_t));

  uint16_t i;
  uint16_t j;
  uint16_t m;

  __m128i abroad[8];

  __m128i cur;
  __m128i next;
  __m128i x2;
  for(i=0; i<padN/8; i++)
  {
    /* Broadcast each of the uint16's at a[8*i] into 8
       copies of that value in a separate __m128i. */
    __m128i ai8 = _mm_load_si128((__m128i *) a+i);
    __m128i ai8h = _mm_unpackhi_epi16(ai8,ai8);
    __m128i ai8l = _mm_unpacklo_epi16(ai8,ai8);
    abroad[0] = _mm_shuffle_epi32(ai8h, 0xFFFF);
    abroad[1] = _mm_shuffle_epi32(ai8h, 0xAAAA);
    abroad[2] = _mm_shuffle_epi32(ai8h, 0x5555);
    abroad[3] = _mm_shuffle_epi32(ai8h, 0x0000);

    abroad[4] = _mm_shuffle_epi32(ai8l, 0xFFFF);
    abroad[5] = _mm_shuffle_epi32(ai8l, 0xAAAA);
    abroad[6] = _mm_shuffle_epi32(ai8l, 0x5555);
    abroad[7] = _mm_shuffle_epi32(ai8l, 0x0000);

    /* Load a 256 bit section of b.
       Shift it down by 2*(m+1) bytes and multiply the
       low 128 bits by abroad[m]. Add all 8 of these
       values to T[i+j]. */
    cur = _mm_setzero_si128();
    for(j=0; j<(padN/8); j++)
    {
      next = _mm_load_si128((__m128i *) b+j);

      x2 = _mm_xor_si128(x2,x2);
      for(m=0; m<8; m++)
      {
        cur = _mm_alignr_epi8(next, cur, 2);
        next = _mm_srli_si128(next, 2);

        __m128i x1 = _mm_mullo_epi16(cur, abroad[m]);
        x2 = _mm_add_epi16(x2, x1);
      }
      x2 = _mm_add_epi16(x2, _mm_load_si128(T+i+j));
      _mm_store_si128(T+i+j, x2);
    }

    /* Handle the last N&7 coefficients from a */
    x2 = _mm_xor_si128(x2,x2);
    for(m=0; m < (N&7); m++)
    {
      cur = _mm_srli_si128(cur, 2);

      __m128i x1 = _mm_mullo_epi16(cur, abroad[m]);
      x2 = _mm_add_epi16(x2, x1);
    }
    _mm_store_si128(T+i+j, x2);
  }

  memcpy(res1, T, 2*N*sizeof(uint16_t));

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
    uint16_t        N,          /*  in - degree of (x^N - 1) */
    uint16_t        padN,       /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *tmp,        /*  in - temp buffer of 3*padN elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t i;
    uint16_t q_mask = q-1;

    grade_school_mul(tmp, tmp+2*padN, a, b, N);

    for(i=0; i<N; i++)
    {
        c[i] = (tmp[i] + tmp[i+N]) & q_mask;
    }

    return;
}
