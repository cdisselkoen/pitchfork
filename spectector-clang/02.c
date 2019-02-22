#include <string.h>
#include <stdlib.h>
#include <stdint.h>

unsigned int array1_size = 16;
uint8_t array1[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t array2[256 * 512];
uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

void leakByteLocalFunction(uint8_t k) { temp &= array2[(k)* 512]; }
void victim_function_v02(size_t x) {
     if (x < array1_size) {
       leakByteLocalFunction(array1[x]);
     }
}
