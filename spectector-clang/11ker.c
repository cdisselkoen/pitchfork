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

int mymemcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}

