#include "crypto_scalarmult.h"

static const unsigned char basepoint[32] = {9};

int crypto_scalarmult_base(unsigned char *q,const unsigned char *n)
{
  return crypto_scalarmult(q, n, basepoint);
}

int crypto_scalarmult_base_lfence(unsigned char *q,const unsigned char *n)
{
  return crypto_scalarmult_lfence(q, n, basepoint);
}
