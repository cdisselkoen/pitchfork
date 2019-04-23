#include <stdio.h>
#include <string.h>

#include "crypto_scalarmult.h"

int main(void)
{
  unsigned char n[32];
  unsigned char q0[32];
  unsigned char q1[32];

  FILE *urandom = fopen("/dev/urandom", "r");

  fread(n, 1, 32, urandom);
  
  fclose(urandom);

  crypto_scalarmult_base(q0, n);
  crypto_scalarmult_base_lfence(q1, n);

  if(memcmp(q0, q1, 32))
  {
    printf("error\n");
    return -1;
  }
    
  return 0;
}
