#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"


/* Note: the ntru_crypto library is not designed to allow direct access to
 * parameter sets, nor is it designed to let you use custom parameter sets,
 * so all of this is a bit of a hack.
 */

typedef struct _NTRU_ENCRYPT_PARAM_SET {
    NTRU_ENCRYPT_PARAM_SET_ID id;                 /* parameter-set ID */
    const char*               name;                /* human readable param set name */
    uint8_t const             OID[3];             /* pointer to OID */
    uint8_t                   der_id;             /* parameter-set DER id */
    uint8_t                   N_bits;             /* no. of bits in N (i.e. in
                                                     an index */
    uint16_t                  N;                  /* ring dimension */
    uint16_t                  sec_strength_len;   /* no. of octets of
                                                     security strength */
    uint16_t                  q;                  /* big modulus */
    uint8_t                   q_bits;             /* no. of bits in q (i.e. in
                                                     a coefficient */
    bool                      is_product_form;    /* if product form used */
    uint32_t                  dF_r;               /* no. of 1 or -1 coefficients
                                                     in ring elements F, r */
    uint16_t                  dg;                 /* no. - 1 of 1 coefficients
                                                     or no. of -1 coefficients
                                                     in ring element g */
    uint16_t                  m_len_max;          /* max no. of plaintext
                                                     octets */
    uint16_t                  min_msg_rep_wt;     /* min. message
                                                     representative weight */
    uint16_t                  no_bias_limit;      /* limit for no bias in
                                                     IGF-2 */
    uint8_t                   c_bits;             /* no. bits in candidate for
                                                     deriving an index in
                                                     IGF-2 */
    uint8_t                   m_len_len;          /* no. of octets to hold
                                                     mLenOctets */
    uint8_t                   min_IGF_hash_calls; /* min. no. of hash calls for
                                                     IGF-2 */
    uint8_t                   min_MGF_hash_calls; /* min. no. of hash calls for
                                                     MGF-TP-1 */
} NTRU_ENCRYPT_PARAM_SET;


NTRU_ENCRYPT_PARAM_SET *
ntru_encrypt_get_params_with_id(
    NTRU_ENCRYPT_PARAM_SET_ID id);


static uint8_t
get_entropy(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    static int fd = -1;
    int i;

    if (fd == -1) {
      for (;;) {
        fd = open("/dev/urandom",O_RDONLY);
        if (fd != -1) break;
        sleep(1);
      }
    }

    if (cmd == INIT) {
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        *out = 1;
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY) {
        i = read(fd,out,1);
        while (i < 1) {
          sleep(1);
          i = read(fd,out,1);
        }
        return 1;
    }
    return 0;
}




static void
output_public_key(
    uint16_t        in_len,         /*  in - no. of octets to be unpacked */
    uint8_t const  *in,             /*  in - ptr to octets to be unpacked */
    uint8_t         q_bits)         /*  in - no. of bits in output element */
{
    uint16_t  temp;
    uint16_t  mask;
    uint16_t  shift;
    uint16_t  i;
    uint16_t  third;
    uint16_t  coeff;

    uint16_t nocomma = 1;

    in += 5;
    in_len -= 5;

    /* Keys are stored as h = p*g/f with p=3, so we'll divide by 3 before
     * printing */
    if(q_bits == 8 || q_bits == 9) {
      third = 171;
    } else if(q_bits == 10 || q_bits == 11) {
      third = 683;
    } else if(q_bits == 12 || q_bits == 13) {
      third = 2731;
    } else {
      fprintf(stderr, "q error\n");
      return;
    }

    /* unpack */

    temp = 0;
    mask = (1 << q_bits) - 1;
    shift = q_bits;
    i = 0;

    fprintf(stderr, "[");
    while (i < in_len) 
    {
        if (shift > 8)
        {
            /* the current octet will not fill the current element */

            shift = shift - 8;
            temp |= ((uint16_t)in[i]) << shift;
        }
        else
        {
            /* add bits from the current octet to fill the current element and
             * output the element
             */

            shift = 8 - shift;

            temp |= ((uint16_t)in[i]) >> shift;
            coeff = temp & mask;
            coeff *= third;
            coeff &= (1<<q_bits)-1;
            if(nocomma){
              fprintf(stderr, "%d", coeff);
              nocomma = 0;
            }else{
              fprintf(stderr, ", %d", coeff);
            }

            /* add the remaining bits of the current octet to start an element */ 
            shift = q_bits - shift;
            temp = ((uint16_t)in[i]) << shift;
        }
        ++i;
    }
    fprintf(stderr, "]\n");

    return;
}


int
main(int argc, char **argv)
{
    int i;
    uint8_t *public_key;
    uint8_t *private_key;

    uint16_t public_key_len;          /* no. of octets in public key */
    uint16_t private_key_len;         /* no. of octets in private key */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */

    NTRU_ENCRYPT_PARAM_SET_ID param_set_ids[] = {
      //CHL_63R0,
      CHL_107R0, CHL_113R0, CHL_131R0, CHL_139R0, CHL_149R0,
      CHL_163R0, CHL_173R0, CHL_181R0, CHL_191R0, CHL_199R0, CHL_211R0,
      CHL_227R0, CHL_239R0, CHL_251R0, CHL_263R0, CHL_271R0, CHL_281R0,
      CHL_293R0, CHL_307R0, CHL_317R0, CHL_331R0, CHL_347R0, CHL_359R0,
      CHL_367R0, CHL_379R0, CHL_389R0, CHL_401R0,
    };
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;
    NTRU_ENCRYPT_PARAM_SET *params;

    for(i=0; i<(sizeof(param_set_ids)/sizeof(param_set_id)); i++)
    {
      param_set_id = param_set_ids[i];

      params = ntru_encrypt_get_params_with_id(param_set_id);

      fprintf(stderr, "%s\n", ntru_encrypt_get_param_set_name(param_set_id));
      fprintf(stderr, "N = %d\n", params->N);
      fprintf(stderr, "q = %d\n", params->q);
      fprintf(stderr, "d1 = %d\n", (params->dF_r) & 0xff );
      fprintf(stderr, "d2 = %d\n", (params->dF_r >> 8) & 0xff );
      fprintf(stderr, "d3 = %d\n", (params->dF_r >> 16) & 0xff );
      fprintf(stderr, "dg = %d\n", params->dg);
      fprintf(stderr, "public_key = ");


      fflush (stderr);

      rc = ntru_crypto_drbg_instantiate(256, NULL, 0,
                                        (ENTROPY_FN) &get_entropy, &drbg);

      if (rc != DRBG_OK)
      {
        fprintf(stderr,"\tError: An error occurred instantiating the DRBG\n");
        return 1;
      }

      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           NULL, &private_key_len, NULL);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        fprintf(stderr,"\tError: An error occurred getting the key lengths\n");
        return 1;
      }

      public_key = (uint8_t *)malloc(public_key_len * sizeof(uint8_t));
      private_key = (uint8_t *)malloc(private_key_len * sizeof(uint8_t));

      do {
      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           public_key,
                                           &private_key_len,
                                           private_key);
      } while(rc == NTRU_RESULT(NTRU_FAIL));

      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        free(public_key);
        free(private_key);
        fprintf(stderr,"\tError: An error occurred during key generation %x\n", rc);
        return 1;
      }

      output_public_key(public_key_len, public_key, params->q_bits);

      ntru_crypto_drbg_uninstantiate(drbg);
      free(public_key);
      free(private_key);
      fprintf(stderr, "\n");
    }

    return 0;
}




