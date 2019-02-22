#include <string.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16;
uint8_t array1[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t array2[256 * 512];
uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

// void victim_function_v05(size_t x) {
//   int i;
//   if (x < array1_size) {
//     for (i = x - 1; i >= 0; i--)
//       temp &= array2[array1[i] * 512];
//   }
// }

// Patched version using signed integers (passing MIN_INT as argument
// have problems due to an integer underflow in i=x-1). Spectector
// X86->muAasm does not support unsigned arithmetic yet.
void victim_function_v05(long x) {
  int i;
  if (x >=0 && x < array1_size) {
    for (i = x - 1; i >= 0; i--)
      temp &= array2[array1[i] * 512];
  }
}
