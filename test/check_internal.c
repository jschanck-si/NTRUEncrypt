#include <stdio.h>
#include <stdlib.h>
#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "ntru_crypto_ntru_convert.h"
#include "ntru_crypto_ntru_encrypt_key.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"
#include "ntru_crypto_ntru_poly.h"
#include "test_common.h"


/* TODO: Conditionally compile this memory checking code into test_common.o */
typedef struct _NTRU_CK_MEM {
    uint8_t   *_alloc;
    uint8_t   *ptr;
    size_t     len;
} NTRU_CK_MEM;

uint8_t *
ntru_ck_malloc(NTRU_CK_MEM *obj, size_t size)
{
    uint32_t i;
    obj->_alloc = (uint8_t *)malloc(size+32);
    ck_assert_ptr_ne(obj->_alloc, NULL);
    /* Fill first 16 bytes with random data */
    randombytes(obj->_alloc, 16);
    /* Fill last 16 bytes with bit-wise negation of first 16 */
    for(i=0; i<16; i++)
    {
        obj->_alloc[16+size+i] = ~(obj->_alloc[i]);
    }
    obj->ptr = obj->_alloc+16;
    obj->len = size;

    return obj->ptr;
}

void
ntru_ck_mem_ok(NTRU_CK_MEM *obj)
{
    uint32_t i;
    uint8_t r=0;
    /* check that xor of first 16 bytes with last 16 bytes gives all 1s */
    for(i=0; i<16; i++)
    {
        r |= (obj->_alloc[i] ^ obj->_alloc[16 + obj->len + i]) + 1;
    }
    ck_assert_uint_eq(r, 0);
}

void
ntru_ck_mem_free(NTRU_CK_MEM *obj)
{
    free(obj->_alloc);
    obj->ptr = NULL;
    obj->len = 0;
}


DRBG_HANDLE drbg;

void
test_drbg_setup(void)
{
    uint32_t rc;
    rc = ntru_crypto_external_drbg_instantiate(
                                    (RANDOM_BYTES_FN) &randombytes, &drbg);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
}

void
test_drbg_teardown(void)
{
    uint32_t rc;
    rc = ntru_crypto_drbg_uninstantiate(drbg);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));
}

START_TEST(test_gen_poly)
{

    uint32_t  rc;
    uint32_t  i;
    uint32_t  j;

    uint8_t   md_len;
    uint16_t  seed_len;
    uint16_t  mgf_buf_len;
    uint16_t  num_indices = 0;

    NTRU_ENCRYPT_PARAM_SET *params = NULL;
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;
    NTRU_CRYPTO_HASH_ALGID  hash_algid;

    uint8_t  *seed_buf_p;
    uint8_t  *mgf_buf_p;
    uint16_t  *F_buf_1_p;
    uint16_t  *F_buf_2_p;

    NTRU_CK_MEM seed_buf;
    NTRU_CK_MEM mgf_buf;
    NTRU_CK_MEM F_buf_1;
    NTRU_CK_MEM F_buf_2;

    /* Get the parameter set */
    param_set_id = PARAM_SET_IDS[_i];
    params = ntru_encrypt_get_params_with_id(param_set_id);
    ck_assert_ptr_ne(params, NULL);

    if (params->sec_strength_len <= 20)
    {
        hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA1;
        md_len = 20;
    }
    else
    {
        hash_algid = NTRU_CRYPTO_HASH_ALGID_SHA256;
        md_len = 32;
    }

    seed_len = params->sec_strength_len + 8;
    mgf_buf_len = 4 + params->N + md_len * (1+params->min_IGF_hash_calls);

    if(params->is_product_form)
    {
        /* Need 2 * (dF1 + dF2 + dF3) indices) */
        num_indices = (params->dF_r & 0x000000ff);
        num_indices += (params->dF_r & 0x0000ff00) >> 8;
        num_indices += (params->dF_r & 0x00ff0000) >> 16;
        num_indices *= 2;
    }
    else
    {
        num_indices = 2 * params->dF_r;
    }

    seed_buf_p = ntru_ck_malloc(&seed_buf, seed_len*sizeof(*seed_buf_p));
    mgf_buf_p = ntru_ck_malloc(&mgf_buf, mgf_buf_len*sizeof(*mgf_buf_p));
    F_buf_1_p = (uint16_t *) ntru_ck_malloc(&F_buf_1,
            num_indices*sizeof(F_buf_1_p));
    F_buf_2_p = (uint16_t *) ntru_ck_malloc(&F_buf_2,
            num_indices*sizeof(F_buf_2_p));

    /* Generate a random seed */
    rc = ntru_crypto_drbg_generate(drbg, params->sec_strength_len << 3,
                                   seed_len, seed_buf_p);
    ck_assert_uint_eq(rc, DRBG_RESULT(DRBG_OK));

    /* Generate an "F" type polynomial for this parameter set */
    rc = ntru_gen_poly(hash_algid, md_len,
                       params->min_IGF_hash_calls,
                       seed_len, seed_buf_p, mgf_buf_p,
                       params->N, params->c_bits,
                       params->no_bias_limit,
                       params->is_product_form,
                       params->dF_r << 1, F_buf_1_p);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    /* Check that indices are pairwise distinct (per poly for prod-form) */
    if(params->is_product_form)
    {
        uint16_t *Fp;
        uint32_t c;

        Fp = F_buf_1_p;
        c = params->dF_r << 1;
        while(c > 0) /* High byte of c is 0x00 */
        {
            for(i=0; i<(c&0xff)-1; i++)
            {
                for(j=i+1; j<(c&0xff); j++)
                {
                    ck_assert_uint_ne(Fp[i], Fp[j]);
                }
            }
            Fp += c & 0xff;
            c >>= 8;
        }
    }
    else
    {
        for(i=0; i<2*params->dF_r - 1; i++)
        {
            for(j=i+1; j<2*params->dF_r; j++)
            {
                ck_assert_uint_ne(F_buf_1_p[i], F_buf_1_p[j]);
            }
        }
    }

    /* Check that we get the same polynomial if we reuse the seed */
    rc = ntru_gen_poly(hash_algid, md_len,
                       params->min_IGF_hash_calls,
                       seed_len, seed_buf_p, mgf_buf_p,
                       params->N, params->c_bits,
                       params->no_bias_limit,
                       params->is_product_form,
                       params->dF_r << 1, F_buf_2_p);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));
    ck_assert_int_eq(
            memcmp(F_buf_1_p, F_buf_2_p, num_indices*sizeof(uint16_t)), 0);


    ntru_ck_mem_ok(&F_buf_2);
    ntru_ck_mem_ok(&F_buf_1);
    ntru_ck_mem_ok(&mgf_buf);
    ntru_ck_mem_ok(&seed_buf);

    ntru_ck_mem_free(&F_buf_2);
    ntru_ck_mem_free(&F_buf_1);
    ntru_ck_mem_free(&mgf_buf);
    ntru_ck_mem_free(&seed_buf);
}
END_TEST

START_TEST(test_min_weight)
{
    uint8_t tpoly1[13] = {2, 2, 2, 2, 0, 0, 0, 0, 0, 1, 1, 1, 1};
    ck_assert_int_eq(ntru_poly_check_min_weight(13, tpoly1, 4), TRUE);
    ck_assert_int_eq(ntru_poly_check_min_weight(13, tpoly1, 5), FALSE);
}
END_TEST

/* test_inv_mod_2
 *
 * Compares the result of ntru_ring_inv to a fixed value precomputed
 * with Pari/GP. Also checks that non-trivial non-invertible elements (factors
 * of x^N - 1 mod 2) are recognized as such.
 */
START_TEST(test_inv_mod_2)
{
    uint16_t tmp[34];
    uint16_t out[17];

    uint16_t a[17] = {1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1};
    uint16_t test_a[17] = {1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1};

    uint16_t b[17] = {1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0};

    /* a is invertible with inverse equal to test_a */
    ck_assert_int_eq(ntru_ring_inv(a, 17, tmp, out), TRUE);
    ck_assert_int_eq(memcmp(out, test_a, sizeof(a)), 0);

    /* Changing the parity of a makes it trivially non-invertible */
    a[0] = 0;
    ck_assert_int_eq(ntru_ring_inv(a, 17, tmp, out), FALSE);

    /* b is a nontrivial factor of x^17 - 1 mod 2 */
    ck_assert_int_eq(ntru_ring_inv(b, 17, tmp, out), FALSE);
}
END_TEST


/* test_mult_indices
 *
 * Performs both ntru_ring_mult_indices and ntru_ring_mult_product_indices
 * and compares the result with a fixed example generated with Pari/GP.
 */
START_TEST(test_mult_indices)
{
    uint32_t i;
    uint16_t a[17] = {36486, 20395, 8746, 16637, 26195, 1654, 24222, 13306,
                    9573, 26946, 29106, 2401, 32146, 2871, 41930, 7902, 3398};
    uint16_t b1l = 2;
    uint16_t b2l = 2;
    uint16_t b3l = 3;
    uint16_t bi[14] = {7, 10, 9, 13, 1, 13, 6, 8, 4, 10, 11, 6, 9, 15};
    uint16_t test_single[17] = {6644, 48910, 5764, 16270, 2612, 10231, 769,
        2577, 58289, 38323, 56334, 29942, 55901, 43714, 17452, 43795, 21225};
    uint16_t test_prod[17] = {40787, 24792, 27808, 13989, 56309, 37625, 37436,
        32307, 15311, 59789, 32769, 65008, 3711, 54663, 25343, 55984, 6193};

    uint16_t N = 17;
    uint16_t q = 0;

    NTRU_CK_MEM pol1;
    NTRU_CK_MEM t;
    NTRU_CK_MEM out;

    uint16_t *pol1_p;
    uint16_t *t_p;
    uint16_t *out_p;

    uint16_t scratch_polys;
    uint16_t pad_deg;
    ntru_ring_mult_indices_memreq(N, &scratch_polys, &pad_deg);
    ck_assert_uint_ge(scratch_polys, 1);
    ck_assert_uint_ge(pad_deg, N);

    pol1_p = (uint16_t*)ntru_ck_malloc(&pol1, pad_deg*sizeof(*pol1_p));
    t_p = (uint16_t*)ntru_ck_malloc(&t, (scratch_polys+1)*pad_deg*sizeof(*t_p));
    out_p = (uint16_t*)ntru_ck_malloc(&out, pad_deg*sizeof(*out_p));

    /* Copy and pad the input */
    memset(pol1.ptr, 0, pol1.len);
    memcpy(pol1_p, a, N*sizeof(uint16_t));

    /* We should be able to work with dirty scratch and output memory */
    randombytes(t.ptr, t.len);
    randombytes(out.ptr, out.len);

    /* Test a single mult_indices first */
    ntru_ring_mult_indices(pol1_p, b1l, b1l, bi, N, q, t_p, out_p);
    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test_single[i]);
    } /* Check padding is zero */
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&t);
    ntru_ck_mem_ok(&out);

    /* Now try a full product form multiplication */
    randombytes(t.ptr, t.len);
    randombytes(out.ptr, out.len);

    /* Multiply */
    ntru_ring_mult_product_indices(pol1_p, b1l, b2l, b3l, bi, N, q, t_p, out_p);

    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test_prod[i]);
    } /* Check padding is zero */
    for(; i<pad_deg; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&t);
    ntru_ck_mem_ok(&out);

    ntru_ck_mem_free(&pol1);
    ntru_ck_mem_free(&t);
    ntru_ck_mem_free(&out);
}
END_TEST


START_TEST(test_mult_coefficients)
{
    uint32_t i;
    uint16_t a[17] = {36486, 20395, 8746, 16637, 26195, 1654, 24222, 13306,
                9573, 26946, 29106, 2401, 32146, 2871, 41930, 7902, 3398};
    uint16_t b[17] = {5266, 35261, 54826, 45380, 46459, 46509, 56767, 46916,
                33670, 11921, 46519, 47628, 20388, 4167, 39405, 2712, 52748};
    uint16_t test[17] = {30101, 45125, 62370, 2275, 34473, 7074, 62574, 57665,
                5199, 4482, 49487, 17159, 33125, 11061, 19328, 22268, 46230};

    uint16_t N = 17;
    uint16_t q = 0;

    /* Determine proper padding for our mult implementation */
    uint16_t num_polys;
    uint16_t num_coeffs;
    ntru_ring_mult_coefficients_memreq(N, &num_polys, &num_coeffs);

    /* Allocate memory */
    NTRU_CK_MEM pol1;
    NTRU_CK_MEM pol2;
    NTRU_CK_MEM tmp;
    NTRU_CK_MEM out;

    uint16_t *a_p;
    uint16_t *b_p;
    uint16_t *tmp_p;
    uint16_t *out_p;

    a_p = (uint16_t*)ntru_ck_malloc(&pol1, num_coeffs*sizeof(uint16_t));
    b_p = (uint16_t*)ntru_ck_malloc(&pol2, num_coeffs*sizeof(uint16_t));
    tmp_p = (uint16_t*)ntru_ck_malloc(&tmp,
            num_polys*num_coeffs*sizeof(uint16_t));
    out_p = (uint16_t*)ntru_ck_malloc(&out, num_coeffs*sizeof(uint16_t));

    /* Copy and pad the inputs */
    memcpy(a_p, a, N*sizeof(uint16_t));
    memcpy(b_p, b, N*sizeof(uint16_t));
    memset(a_p+N, 0, (num_coeffs-N)*sizeof(uint16_t));
    memset(b_p+N, 0, (num_coeffs-N)*sizeof(uint16_t));

    /* Should work with dirty scratch and output memory */
    randombytes(tmp.ptr+N, (num_coeffs-N)*sizeof(uint16_t));
    randombytes(out.ptr, out.len);

    /* Multiply */
    ntru_ring_mult_coefficients(a_p, b_p, N, q, tmp_p, out_p);

    /* Check result */
    for(i=0; i<N; i++)
    {
        ck_assert_uint_eq(out_p[i], test[i]);
    } /* Padding should be zero */
    for(; i<num_coeffs; i++)
    {
        ck_assert_uint_eq(out_p[i], 0);
    }

    /* Check over/under runs */
    ntru_ck_mem_ok(&pol1);
    ntru_ck_mem_ok(&pol2);
    ntru_ck_mem_ok(&tmp);
    ntru_ck_mem_ok(&out);

    ntru_ck_mem_free(&pol1);
    ntru_ck_mem_free(&pol2);
    ntru_ck_mem_free(&tmp);
    ntru_ck_mem_free(&out);
}
END_TEST


/*
 * test_key_form
 *
 * For all parameter sets:
 * Check that keys satisfy h = pf/g with f and g of the
 * correct form by computing f*h.
 */
START_TEST(test_key_form)
{
    uint32_t i;
    uint32_t rc;

    NTRU_CK_MEM pubkey_blob;
    NTRU_CK_MEM privkey_blob;
    NTRU_CK_MEM F_buf;
    NTRU_CK_MEM h_poly;
    NTRU_CK_MEM g_poly;
    NTRU_CK_MEM scratch;

    uint8_t *pubkey_blob_p;
    uint8_t *privkey_blob_p;

    uint8_t const *pubkey_pack_p;
    uint8_t const *privkey_pack_p;

    uint16_t *F_buf_p;
    uint16_t *h_poly_p;
    uint16_t *g_poly_p;
    uint16_t *scratch_p;

    uint16_t pubkey_blob_len = 0;
    uint16_t privkey_blob_len = 0;
    uint16_t pubkey_pack_len = 0;

    uint8_t pubkey_pack_type = 0x00;
    uint8_t privkey_pack_type = 0x00;

    uint16_t mod_q_mask;
    uint16_t h1;
    uint32_t dF;

    uint16_t scratch_polys;
    uint16_t pad_deg;

    NTRU_ENCRYPT_PARAM_SET *params = NULL;
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;

    param_set_id = PARAM_SET_IDS[_i];
    params = ntru_encrypt_get_params_with_id(param_set_id);
    ck_assert_ptr_ne(params, NULL);

    mod_q_mask = params->q - 1;
    ntru_ring_mult_indices_memreq(params->N, &scratch_polys, &pad_deg);
    ck_assert_uint_ge(scratch_polys, 1);
    ck_assert_uint_ge(pad_deg, params->N);

    if(params->is_product_form)
    {
        scratch_polys += 1;
    }

    /* Generate a key */
    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &pubkey_blob_len,
                                         NULL, &privkey_blob_len, NULL);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    pubkey_blob_p = ntru_ck_malloc(&pubkey_blob,
            pubkey_blob_len*sizeof(*pubkey_blob_p));

    privkey_blob_p = ntru_ck_malloc(&privkey_blob,
            privkey_blob_len*sizeof(*privkey_blob_p));

    rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id,
                                         &pubkey_blob_len, pubkey_blob_p,
                                         &privkey_blob_len, privkey_blob_p);
    ck_assert_uint_eq(rc, NTRU_RESULT(NTRU_OK));

    rc = ntru_crypto_ntru_encrypt_key_parse(FALSE,
                                            privkey_blob_len,
                                            privkey_blob_p, &pubkey_pack_type,
                                            &privkey_pack_type, &params,
                                            &pubkey_pack_p, &privkey_pack_p);
    ck_assert_int_eq(rc, TRUE);

    h_poly_p = (uint16_t*) ntru_ck_malloc(&h_poly, pad_deg*sizeof(*h_poly_p));

    /* Unpack public key, h */
    pubkey_pack_len = (params->N * params->q_bits + 7) >> 3;
    ntru_octets_2_elements(pubkey_pack_len, pubkey_pack_p,
                           params->q_bits, h_poly_p);

    /* Check that h(1) = p * f(1)/g(1) = 3 */
    h1 = 0;
    for(i=0; i<params->N; i++)
    {
        h1 += h_poly_p[i];
    }
    h1 &= mod_q_mask;
    ck_assert_uint_eq(h1, 3);

    /* Unpack private key, F */
    dF = params->dF_r;
    if (params->is_product_form)
    {
        dF = (dF + (dF >> 8) + (dF >> 16)) & 0xff;
    }

    F_buf_p = (uint16_t*)ntru_ck_malloc(&F_buf, 2*dF*sizeof(*F_buf_p));

    if (privkey_pack_type == NTRU_ENCRYPT_KEY_PACKED_TRITS)
    {
        ntru_packed_trits_2_indices(privkey_pack_p, params->N, F_buf_p,
                                    F_buf_p + dF);
   }
    else if (privkey_pack_type == NTRU_ENCRYPT_KEY_PACKED_INDICES)
    {
        ntru_octets_2_elements(
                (2 * dF * params->N_bits + 7) >> 3,
                privkey_pack_p, params->N_bits, F_buf_p);
    }

    g_poly_p = (uint16_t*) ntru_ck_malloc(&g_poly, pad_deg*sizeof(*g_poly_p));

    scratch_p = (uint16_t*) ntru_ck_malloc(&scratch,
            scratch_polys*pad_deg*sizeof(*scratch_p));

    /* Check that (1 + p*F)*h = p*g */
    /* Our h = p*g/f when generated properly. f = 1 + pF */
    /* First compute g' = F*h */
    if (params->is_product_form)
    {
        ntru_ring_mult_product_indices(h_poly_p,
                                       (uint16_t)(params->dF_r & 0xff),
                                       (uint16_t)((params->dF_r >> 8) & 0xff),
                                       (uint16_t)((params->dF_r >> 16) & 0xff),
                                       F_buf_p, params->N, params->q,
                                       scratch_p, g_poly_p);
    }
    else
    {
        ntru_ring_mult_indices(h_poly_p, (uint16_t)dF, (uint16_t)dF,
                               F_buf_p, params->N, params->q,
                               scratch_p, g_poly_p);
    }
    /* Then g = 3*g' + h */
    for(i=0; i<params->N; i++)
    {
        g_poly_p[i] = (3*g_poly_p[i] + h_poly_p[i]) & mod_q_mask;
    }

    /* Ensure g is of the right form: dg+1 coeffs = +3 and dg coeffs = -3 */
    uint16_t g_p1 = 0;
    uint16_t g_m1 = 0;
    for(i=0; i<params->N; i++)
    {
        if(g_poly_p[i] == 3)
        {
            g_p1 += 1;
        }
        else if(g_poly_p[i] == params->q - 3)
        {
            g_m1 += 1;
        }
        else
        {
            ck_assert_uint_eq(g_poly_p[i], 0);
        }
    }
    ck_assert_uint_eq(g_p1, params->dg + 1);
    ck_assert_uint_eq(g_m1, params->dg);

    ntru_ck_mem_ok(&scratch);
    ntru_ck_mem_ok(&g_poly);
    ntru_ck_mem_ok(&h_poly);
    ntru_ck_mem_ok(&F_buf);
    ntru_ck_mem_ok(&privkey_blob);
    ntru_ck_mem_ok(&pubkey_blob);
}
END_TEST


Suite *
ntruencrypt_internal_test_suite(void)
{
    Suite *s;
    TCase *tc_poly;
    TCase *tc_key;

    s = suite_create("NTRUEncrypt.Internal");

    tc_poly = tcase_create("Poly");
    tcase_add_unchecked_fixture(tc_poly, test_drbg_setup, test_drbg_teardown);
    tcase_add_loop_test(tc_poly, test_gen_poly, 0, NUM_PARAM_SETS);
    tcase_add_test(tc_poly, test_min_weight);
    tcase_add_test(tc_poly, test_inv_mod_2);
    tcase_add_test(tc_poly, test_mult_indices);
    tcase_add_test(tc_poly, test_mult_coefficients);

    tc_key = tcase_create("Key");
    tcase_add_unchecked_fixture(tc_key, test_drbg_setup, test_drbg_teardown);
    tcase_add_loop_test(tc_key, test_key_form, 0, NUM_PARAM_SETS);

    suite_add_tcase(s, tc_poly);
    suite_add_tcase(s, tc_key);

    return s;
}

int
main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = ntruencrypt_internal_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
