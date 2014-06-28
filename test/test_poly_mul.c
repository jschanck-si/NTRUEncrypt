#include "ntru_crypto_ntru_poly.h"
#include <stdio.h>

#ifdef TEST_COMPARE_CONVOLUTIONS 


#define NDEF (29)
#define DF (5)

int inner_loop(
  uint16_t N, 
  uint16_t bi_P1_len, 
  uint16_t bi_M1_len,
  int print,
  int random_init)
{
  uint16_t *a;
  uint16_t *b;
  uint16_t *t;
  uint16_t *cOrig;
  uint16_t *cDouble;

  uint16_t q = 2048;
  uint16_t mult = 337;
  uint16_t offset = 541;
  int i, j;
  uint16_t tmp;
  int rval = 0;

  a = malloc(N * sizeof (uint16_t));
  b = malloc((bi_P1_len + bi_M1_len) * sizeof (uint16_t));
  cOrig = malloc(N * sizeof (uint16_t));
  cDouble = malloc(N * sizeof (uint16_t));
  t = malloc(N * sizeof (uint16_t));

  if (print) {
    printf("%5d %5d %5d %s\r", N, bi_P1_len, bi_M1_len, 
      random_init? "true" : "false");
    fflush(stdout);
  }

  if (!a || !b || !cOrig || !cDouble || !t) {
    fprintf(stderr, "Out of memory!\n");
    exit (1);
  }

  /* quick and dirty pseudorandom initialization with LCG */

  /* initialize a */
  a[0] = mult;
  for (i = 1; i < N; i++)
    a[i] = (a[i-1]*mult + offset) % q;

  /* initialize b */
  mult = 37;
  offset = 41;
  if (N % offset == 0) offset += 1;
  b[0] = 2;

  if (!random_init) { /* initialize with easy-to-debug pattern */
    for (i = 1; i < bi_P1_len+bi_M1_len; i++) {
      b[i] = b[i-1]+2;
    } /* for (i = 0; i < bi_P1_len+bi_M1_len; i++) */
  } 
  else { /* initialize pseudo-randomly */
    for (i = 1; i < bi_P1_len+bi_M1_len; i++) {
      int match;
  
      /* Generate candidate b[i] */
      tmp = (b[i-1]*mult) % N; 
  
      /* Check it doesn't match a previous b[i] */
      match = 1;
      while (match == 1) {
        tmp += offset;
        tmp %= N;
        match = 0;
        for (j = 0; j < i; j++) {
          if (b[j] == tmp) {
            match = 1;
            break;
          }
        } /* check for match */
      } /* while match == 1 */
      b[i] = tmp;
    } /* for (i = 0; i < bi_P1_len+bi_M1_len; i++) */
  }
    
  /* multiply and compare */
  ntru_ring_mult_indices_orig
    (a, bi_P1_len, bi_M1_len, b, N, q, t, cOrig);

  ntru_ring_mult_indices_quadruple_width_conv
    (a, bi_P1_len, bi_M1_len, b, N, q, t, cDouble);

  if (memcmp(cOrig, cDouble, N*sizeof(uint16_t))) {
    rval = 1;
  
    printf ("\nError!\n");
    /* print a */
    printf ("a:\n ");
    for (i = 0; i < N; i++) {
      printf ("%04x ", a[i]);
      if (i % 16 == 15) printf ("\n ");
    }
    printf("\n");
      
    /* print b, plus indices then minus indices */
    printf ("b:\n ");
    for (i = 0; i < bi_P1_len; i++) {
      printf ("%3d ", b[i]);
      if (i % 16 == 15) printf ("\n ");
    }
    printf("\n ");
    for (i = 0; i < bi_M1_len; i++) {
      printf ("%3d ", b[i+bi_P1_len]);
      if (i % 16 == 15) printf ("\n ");
    }
    printf("\n ");
      
    printf ("result of original mult:\n ");
    for (i = 0; i < N; i++) {
      printf ("%04x ", cOrig[i]);
      if (i % 16 == 15) printf ("\n ");
    }
    printf("\n");
      
    printf ("result of double-width mult:\n ");
    for (i = 0; i < N; i++) {
      printf ("%04x ", cDouble[i]);
      if (i % 16 == 15) printf ("\n ");
    }
    printf("\n");
  }

  free(a); free(b); free(cOrig); free(cDouble); free(t);

  return rval;
}

int
main ()
{
  int rval;
  uint16_t N;
  uint16_t df;

  uint16_t tmp[] = {0, 1, 2, 3, 4};
  uint32_t *t1 = (uint32_t*)&tmp[0];
  uint32_t *t2 = (uint32_t*)&tmp[1];
  *t2 += *t1;

/*
  rval = inner_loop(29, 5, 5, 1, 1);
  if (rval) exit (rval);
*/

  for (N = 29; N < 1000; N+=30) {
    for (df = 5; df < N/3; df+= 5) {
    
      rval = inner_loop(N, df, 0, 1, 1);
      if (rval) exit (rval);

      rval = inner_loop(N, 0, df, 1, 1);
      if (rval) exit (rval);

      rval = inner_loop(N, df, df, 1, 1);
      if (rval) exit (rval);
    }
  }
  printf("\nSuccess!\n");

  exit (0);
}

#else  /* def/ndef TEST_COMPARE_CONVOLUTIONS  */

int main()
{
  printf(
    "\n\n    **************************\n\n"
    "compile this test program and the library with -DTEST_COMPARE_CONVOLUTIONS"
    "\nto run these tests.\n"
    "\n    **************************\n\n"
  );
  exit (0);
}

#endif  /* def TEST_COMPARE_CONVOLUTIONS  */
