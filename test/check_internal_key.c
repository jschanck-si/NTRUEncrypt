#include <check.h>

#include "ntru_crypto.h"
#include "ntru_crypto_ntru_convert.h"
#include "ntru_crypto_ntru_encrypt_key.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"
#include "ntru_crypto_ntru_poly.h"

#include "test_common.h"
#include "check_common.h"

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
ntruencrypt_internal_key_suite(void)
{
    Suite *s;
    TCase *tc_key;

    s = suite_create("NTRUEncrypt.Internal.Key");

    tc_key = tcase_create("Key");
    tcase_add_unchecked_fixture(tc_key, test_drbg_setup, test_drbg_teardown);
    tcase_add_loop_test(tc_key, test_key_form, 0, NUM_PARAM_SETS);

    suite_add_tcase(s, tc_key);

    return s;
}

