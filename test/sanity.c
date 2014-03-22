#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntru_crypto.h"
#include "ntru_crypto_ntru_encrypt_param_sets.h"

/* For each parameter set:
 *    - Generate a key
 *    - Encrypt a message at every length between
 *      0 and maxMsgLenBytes.
 *    - Check that decryption succeeds.
 *    - TODO: Check that decryption fails for bad ciphertexts
 */

#define RAND_LEN (4096)
static void randombytes(uint8_t *x,uint64_t xlen)
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

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

static uint8_t
get_entropy(
    ENTROPY_CMD  cmd,
    uint8_t     *out)
{
    /* 21 bytes of entropy are needed to instantiate a DRBG with a
     * security strength of 112 bits.
     */
    static uint8_t randpool[RAND_LEN];
    static size_t index;

    if (cmd == INIT) {
        /* Any initialization for a real entropy source goes here. */
        randombytes(randpool, sizeof(randpool));
        index = 0;
        return 1;
    }

    if (out == NULL)
        return 0;

    if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
        /* Here we return the number of bytes needed from the entropy
         * source to obtain 8 bits of entropy.  Maximum is 8.
         */
        *out = 1;                       /* this is a perfectly random source */
        return 1;
    }

    if (cmd == GET_BYTE_OF_ENTROPY) {
        if (index == sizeof(randpool)) {
            randombytes(randpool, RAND_LEN);
            index = 0;
        }

        *out = randpool[index++];           /* deliver an entropy byte */
        return 1;
    }
    return 0;
}



int
main(void)
{
    int i;
    uint8_t *public_key;
    uint8_t *private_key;
    uint8_t *message;
    uint8_t *ciphertext;
    uint8_t *plaintext;

    uint16_t max_msg_len;
    uint16_t mlen;
    uint16_t public_key_len;          /* no. of octets in public key */
    uint16_t private_key_len;         /* no. of octets in private key */
    uint16_t ciphertext_len;          /* no. of octets in ciphertext */
    uint16_t plaintext_len;           /* no. of octets in plaintext */
    DRBG_HANDLE drbg;                 /* handle for instantiated DRBG */
    uint32_t rc;                      /* return code */
    uint16_t drbg_strength;

    NTRU_ENCRYPT_PARAM_SET_ID param_set_ids[] = {
      NTRU_EES401EP1, NTRU_EES449EP1, NTRU_EES677EP1, NTRU_EES1087EP2,
      NTRU_EES541EP1, NTRU_EES613EP1, NTRU_EES887EP1, NTRU_EES1171EP1,
      NTRU_EES659EP1, NTRU_EES761EP1, NTRU_EES1087EP1, NTRU_EES1499EP1,
      NTRU_EES401EP2, NTRU_EES439EP1, NTRU_EES593EP1, NTRU_EES743EP1
    };
    NTRU_ENCRYPT_PARAM_SET_ID param_set_id;
    NTRU_ENCRYPT_PARAM_SET *param_set;

    uint32_t error[(sizeof(param_set_ids)/sizeof(param_set_id))] = {0};

    for(i=0; i<(sizeof(param_set_ids)/sizeof(param_set_id)); i++)
    {
      param_set_id = param_set_ids[i];
      param_set = ntru_encrypt_get_params_with_id(param_set_id);
      fprintf(stderr, "Testing parameter set with DER id 0x%02x\n", param_set->der_id);


      drbg_strength = param_set->sec_strength_len<<3;
      rc = ntru_crypto_drbg_instantiate(drbg_strength, NULL, 0,
                                        (ENTROPY_FN) &get_entropy, &drbg);
      if (rc != DRBG_OK)
      {
        fprintf(stderr,"\tError: An error occurred instantiating the DRBG\n");
        error[i] = 1;
        continue;
      }

      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           NULL, &private_key_len, NULL);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        fprintf(stderr,"\tError: An error occurred getting the key lengths\n");
        error[i] = 1;
        continue;
      }

      public_key = (uint8_t *)malloc(public_key_len * sizeof(uint8_t));
      private_key = (uint8_t *)malloc(private_key_len * sizeof(uint8_t));

      rc = ntru_crypto_ntru_encrypt_keygen(drbg, param_set_id, &public_key_len,
                                           public_key,
                                           &private_key_len,
                                           private_key);
      if (rc != NTRU_OK)
      {
        ntru_crypto_drbg_uninstantiate(drbg);
        free(public_key);
        free(private_key);
        fprintf(stderr,"\tError: An error occurred during key generation\n");
        error[i] = 1;
        continue;
      }

      max_msg_len = param_set->m_len_max;
      message = (uint8_t *) malloc(max_msg_len * sizeof(uint8_t));

      ciphertext_len = (param_set->N * param_set->q_bits + 7) >> 3;
      ciphertext = (uint8_t *) malloc(ciphertext_len * sizeof(uint8_t));

      plaintext_len = max_msg_len;
      plaintext = (uint8_t *) malloc(plaintext_len * sizeof(uint8_t));

      for(mlen=0; mlen<=max_msg_len; mlen++)
      {
        plaintext_len = max_msg_len;
        randombytes(message, mlen);
        randombytes(ciphertext, ciphertext_len);
        randombytes(plaintext, plaintext_len);

        rc = ntru_crypto_ntru_encrypt(drbg, public_key_len, public_key,
                mlen, message, &ciphertext_len, ciphertext);
        if (rc != NTRU_OK){
          fprintf(stderr, "\tError: Encryption error %x\n", rc);
          error[i] = 1;
          break;
        }

        rc = ntru_crypto_ntru_decrypt(private_key_len, private_key,
                ciphertext_len, ciphertext,
                &plaintext_len, plaintext);
        if (rc != NTRU_OK)
        {
          fprintf(stderr, "\tError: Decryption error %x\n", rc);
          error[i] = 1;
          break;
        }

        if(plaintext_len != mlen || memcmp(plaintext,message,mlen))
        {
          fprintf(stderr,
            "\tError: Decrypted plaintext does not match original plaintext\n");
          error[i] = 1;
          break;
        }
      }

      ntru_crypto_drbg_uninstantiate(drbg);
      free(message);
      free(public_key);
      free(private_key);
      free(plaintext);
      free(ciphertext);
    }

    for(i=0; i<(sizeof(param_set_ids)/sizeof(param_set_id)); i++) {
      if(error[i]) {
        fprintf(stderr, "Result: Fail\n");
        return 1;
      }
    }

    fprintf(stderr, "Result: Pass\n");
    return 0;
}
