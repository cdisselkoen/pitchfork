#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_scalarmult.h"
#include "cpucycles.h"

#define NRUNS 1000

static int cmp_llu(const void *a, const void*b)
{
  if(*(unsigned long long *)a < *(unsigned long long *)b) return -1;
  if(*(unsigned long long *)a > *(unsigned long long *)b) return 1;
  return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
  qsort(l,llen,sizeof(unsigned long long),cmp_llu);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}


int main(void)
{
  unsigned char n[32];
  unsigned char q0[32];

  unsigned long long t[NRUNS];
  size_t i;

  FILE *urandom = fopen("/dev/urandom", "r");

  fread(n, 1, 32, urandom);
  
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    crypto_scalarmult_base(q0, n);
  }
  
  for(i=0;i<NRUNS-1;i++)
    t[i] = t[i+1] - t[i];

  printf("Plain median cycles:  %llu\n", median(t, NRUNS-1));
 
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    crypto_scalarmult_base_lfence(q0, n);
  }
  
  for(i=0;i<NRUNS-1;i++)
    t[i] = t[i+1] - t[i];

  printf("lfence median cycles: %llu\n", median(t, NRUNS-1));
    
  return 0;
}
