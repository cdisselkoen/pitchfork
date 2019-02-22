#include <string.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16;
uint8_t array1[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t array2[256 * 512];
uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function_v10(size_t x, uint8_t k) {
     if (x < array1_size) {
          if (array1[x] == k)
               temp &= array2[0];
     }
}
