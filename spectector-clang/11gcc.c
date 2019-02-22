#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <ansidecl.h>

unsigned int array1_size = 16;
uint8_t array1[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t array2[256 * 512];
uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

int mymemcmp (const PTR str1, const PTR str2, size_t count);
void victim_function_v11(size_t x) {
  if (x < array1_size)
    temp = mymemcmp(&temp, array2 + (array1[x] * 512), 1);
}

// Implementation of the semantics on gcc compiler
int mymemcmp (const PTR str1, const PTR str2, size_t count){
  register const unsigned char *s1 = (const unsigned char*)str1;
  register const unsigned char *s2 = (const unsigned char*)str2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
	  return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}
