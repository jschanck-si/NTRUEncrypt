#include "ntru_crypto.h"
#include "ntru_crypto_ntru_poly.h"

static void
grade_school_mul(
    uint16_t        *res1,   /* out - a * b in Z[x], must be length 2N */
    uint16_t        *tmp1,   /*  in - N coefficients of scratch space */
    uint16_t const  *a,     /*  in - polynomial */
    uint16_t const  *b,     /*  in - polynomial */
    uint16_t const   N)     /*  in - number of coefficients in a and b */
{
    uint16_t i;
    uint16_t j;

    for(j=0; j<N; j++)
    {
        res1[j] = a[0]*b[j];
    }
    for(i=1; i<N; i++)
    {
        res1[i+N-1] = 0;
        for(j=0; j<N; j++)
        {
            res1[i+j] += a[i]*b[j];
        }
    }
    res1[2*N-1] = 0;

    return;
}

static void
karatsuba(
    uint16_t        *res1,   /* out - a * b in Z[x], must be length 2k */
    uint16_t        *tmp1,   /*  in - k coefficients of scratch space */
    uint16_t const  *a,     /*  in - polynomial */
    uint16_t const  *b,     /*  in - polynomial */
    uint16_t const   k)     /*  in - number of coefficients in a and b */
{
    uint16_t i;

    /* Grade school multiplication for small / odd inputs */
    if(k <= 38 || (k & 1) != 0)
    {
      grade_school_mul(res1,tmp1,a,b,k);
      return;
    }

    uint16_t const p = k>>1;

    uint16_t *res2 = res1+p;
    uint16_t *res3 = res1+k;
    uint16_t *res4 = res1+k+p;
    uint16_t *tmp2 = tmp1+p;
    uint16_t const *a2 = a+p;
    uint16_t const *b2 = b+p;

    for(i=0; i<p; i++)
    {
        res1[i] = a[i] - a2[i];
        res2[i] = b2[i] - b[i];
    }

    karatsuba(tmp1, res3, res1, res2, p);

    karatsuba(res3, res1, a2, b2, p);

    for(i=0; i<p; i++)
    {
      tmp1[i] += res3[i];
    }

    for(i=0; i<p; i++)
    {
        res2[i]  = tmp1[i];
        tmp2[i] += res4[i];
        res3[i] += tmp2[i];
    }

    karatsuba(tmp1, res1, a, b, p);

    for(i=0; i<p; i++)
    {
        res1[i]  = tmp1[i];
        res2[i] += tmp1[i] + tmp2[i];
        res3[i] += tmp2[i];
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
    uint16_t        N,          /*  in - degree of (x^N - 1) */
    uint16_t        padN,       /*  in - no. of coefficients in a, b, c */
    uint16_t        q,          /*  in - large modulus */
    uint16_t       *tmp,        /*  in - temp buffer of 3*padN elements */
    uint16_t       *c)          /* out - address for polynomial c */
{
    uint16_t i;
    uint16_t q_mask = q-1;

    memset(tmp, 0, 3*padN*sizeof(uint16_t));
    karatsuba(tmp, tmp+2*padN, a, b, N);

    for(i=0; i<N; i++)
    {
        c[i] = (tmp[i] + tmp[i+N]) & q_mask;
    }

    return;
}
