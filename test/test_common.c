#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include "ntru_crypto.h"
#include "ntru_crypto_drbg.h"
#include "test_common.h"

uint32_t randombytes(uint8_t *x,uint64_t xlen)
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
  DRBG_RET(DRBG_OK);
}

