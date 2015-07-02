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


START_TEST(test_inv_mod_2)
{
    uint16_t a[13] = {1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1};
    uint16_t tmp[26];
    uint16_t a_inv[13];
    uint16_t test_a_inv[13] = {0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1};

    randombytes((uint8_t*)tmp, sizeof(tmp));
    randombytes((uint8_t*)a_inv, sizeof(a_inv));

    ck_assert_int_eq(ntru_ring_inv(a, 13, tmp, a_inv), TRUE);
    ck_assert_int_eq(memcmp(a_inv, test_a_inv, sizeof(a)), 0);

    /* Replacing the constant term of a with 0 gives a non-invertible elt */
    a[0] = 0;
    ck_assert_int_eq(ntru_ring_inv(a, 13, tmp, a_inv), FALSE);
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

    NTRU_ENCRYPT_PARAM_SET *params = NULL;
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;

    param_set_id = PARAM_SET_IDS[_i];
    params = ntru_encrypt_get_params_with_id(param_set_id);
    ck_assert_ptr_ne(params, NULL);

    mod_q_mask = params->q - 1;

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

    h_poly_p = (uint16_t*) ntru_ck_malloc(&h_poly, params->N*sizeof(*h_poly_p));

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

    g_poly_p = (uint16_t*) ntru_ck_malloc(&g_poly, params->N*sizeof(*g_poly_p));

    scratch_p = (uint16_t*) ntru_ck_malloc(&scratch,
            2*params->N*sizeof(*scratch_p));

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
