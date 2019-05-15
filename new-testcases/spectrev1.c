// An updated set of the Kocher test cases intended to address two issues:
//
// (1) Spectre violations can be defined as any path where secret data is used
//     in either an address calculation or a branch condition calculation. A
//     desirable property would be that the test cases exhibit no violations
//     when executed _sequentially_, but do exhibit violations when considering
//     speculative execution. Unfortunately, many of the Kocher test cases
//     exhibit violations even when executed sequentially, often because of
//     out-of-bounds errors which exist even on the correct (non-speculative)
//     path. Our updated set of testcases exhibit no violations when executed
//     sequentially.
//
// (2) Which secret data the attacker is trying to leak is somewhat nebulously
//     defined in the original Kocher test cases. Our updated version has an
//     explicit array of secret data which is the attacker's target to leak.

#include <stdint.h>
#include <stddef.h>

// FORCEDINLINE definition from spectector-clang/13.c
#ifdef __MSVC__
#define FORCEDINLINE __forceinline
#define NOINLINE __declspec(noinline)
#else
#define FORCEDINLINE __attribute__((always_inline))
#define NOINLINE __attribute__((noinline))
#endif

uint64_t publicarray_size = 16;
uint8_t publicarray[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t publicarray2[512 * 256] = { 20 };

// The attacker's goal in all of these examples is to learn any of the secret data in secretarray
uint64_t secretarray_size = 16;
uint8_t secretarray[16] = { 10,21,32,43,54,65,76,87,98,109,110,121,132,143,154,165 };

// this is mostly used to prevent the compiler from optimizing out certain operations
volatile uint8_t temp = 0;

// In all of these examples, the arguments to the functions are attacker-controlled

// Kocher test case 1, essentially unmodified
void case_1(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// Kocher test case 2, essentially unmodified
static void leakByteLocalFunction(uint8_t leakThis) { temp &= publicarray2[leakThis * 512]; }
void case_2(uint64_t idx) {
    if (idx < publicarray_size) {
        leakByteLocalFunction(publicarray[idx]);
    }
}

// Kocher test case 3, essentially unmodified
NOINLINE static void leakByteNoinlineFunction(uint8_t leakThis) { temp &= publicarray2[leakThis * 512]; }
void case_3(uint64_t idx) {
    if (idx < publicarray_size) {
        leakByteNoinlineFunction(publicarray[idx]);
    }
}

// Modified version of Kocher test case 4.
// The original version can leak secret information even without speculative
//   execution, i.e., even obeying the bounds check. This version has no
//   out-of-bounds access when executed sequentially.
void case_4(uint64_t idx) {
    if (idx < publicarray_size / 2) {
        temp &= publicarray2[publicarray[idx << 1] * 512];
    }
}

// Kocher test case 5, essentially unmodified
void case_5(uint64_t idx) {
    int64_t i;
    if (idx < publicarray_size) {
        for (i = idx - 1; i >= 0; i--) {
            temp &= publicarray2[publicarray[i] * 512];
        }
    }
}

// Kocher test case 6, essentially unmodified
void case_6(uint64_t idx) {
    // E.g., this mask is 0xf if publicarray_size is 16.
    const uint8_t publicarray_size_mask = publicarray_size - 1;
    if ((idx & publicarray_size_mask) == idx) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// Kocher test case 7, essentially unmodified
void case_7(uint64_t idx) {
    static uint64_t last_idx = 0;
    if (idx == last_idx) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
    if (idx < publicarray_size) {
        last_idx = idx;
    }
}

// Kocher test case 8, included for completeness.
// However, our compiler emits an x86 cmov instruction rather than a conditional
//   branch, which means that the binary code for this test case is indeed
//   safe from Spectre v1 -- no Spectre v1 violation exists.
// This test case has also been slightly modified to avoid out-of-bounds
//   access during sequential execution.
void case_8(uint64_t idx) {
    temp &= publicarray2[publicarray[idx < publicarray_size ? idx : 0] * 512];
}

// Modified version of Kocher test case 9.
// The original version can leak secret information even without speculative
//   execution, under the assumption (which we adopt) that all of the function
//   arguments are attacker-controlled. In the original version, this would
//   allow the attacker to entirely control the outcome of the bounds check
//   even in sequential execution. This version prevents the attacker from
//   controlling the outcome of the bounds check when executed sequentially.
volatile uint8_t idx_is_safe = 0;
void case_9(uint64_t idx) {
    if (idx_is_safe) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// Kocher test case 10, essentially unmodified
void case_10(uint64_t idx, uint8_t val) {
    if (idx < publicarray_size) {
        if (publicarray[idx] == val) {
            temp &= publicarray2[0];
        }
    }
}

// Kocher test case 11, essentially unmodified.
// We include all three variants provided by Spectector, including all three
//   versions of memcmp which they provide.
static int memcmp_gcc(const char* str1, const char* str2, size_t count);
static int memcmp_ker(const void* ptr1, const void* ptr2, size_t count);
static int memcmp_sub(const char* str1, const char* str2, size_t count);
void case_11gcc(uint64_t idx) {
    if (idx < publicarray_size) {
        temp = memcmp_gcc((const char*)&temp, (const char*)(publicarray2 + (publicarray[idx] * 512)), 1);
    }
}
void case_11ker(uint64_t idx) {
    if (idx < publicarray_size) {
        temp = memcmp_ker((const void*)&temp, publicarray2 + (publicarray[idx] * 512), 1);
    }
}
void case_11sub(uint64_t idx) {
    if (idx < publicarray_size) {
        temp = memcmp_sub((const char*)&temp, (const char*)(publicarray2 + (publicarray[idx] * 512)), 1);
    }
}
static int memcmp_gcc(const char* str1, const char* str2, size_t count) {
    register const unsigned char *s1 = (const unsigned char*)str1;
    register const unsigned char *s2 = (const unsigned char*)str2;
    while (count-- > 0) {
        if (*s1++ != *s2++) {
	        return s1[-1] < s2[-1] ? -1 : 1;
        }
    }
    return 0;
}
static int memcmp_ker(const void* ptr1, const void* ptr2, size_t count) {
    const unsigned char *su1, *su2;
    int res = 0;
    for (su1 = ptr1, su2 = ptr2; 0 < count; ++su1, ++su2, count--) {
        if ((res = *su1 - *su2) != 0) {
            break;
        }
    }
    return res;
}
static int memcmp_sub(const char* str1, const char* str2, size_t count) {
    register const unsigned char *s1 = (const unsigned char*)str1;
    register const unsigned char *s2 = (const unsigned char*)str2;
    if(!count) return 0;
    while (--count && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (*s1 - *s2);
}

// Kocher test case 12, essentially unmodified
void case_12(uint64_t x, uint64_t y) {
    if ((x + y) < publicarray_size) {
        temp &= publicarray2[publicarray[x + y] * 512];
    }
}

// Kocher test case 13, essentially unmodified
FORCEDINLINE static int is_idx_safe(uint64_t idx) { if (idx < publicarray_size) return 1; else return 0; }
void case_13(uint64_t idx) {
    if (is_idx_safe(idx)) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// Modified version of Kocher test case 14.
// The original version can leak secret information even without speculative
//   execution, i.e., even obeying the bounds check. This version has no
//   out-of-bounds access when executed sequentially.
void case_14(uint64_t idx) {
    // E.g., this mask is 0xf if publicarray_size is 16.
    const uint8_t publicarray_size_mask = publicarray_size - 1;

    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx ^ publicarray_size_mask] * 512];
    }
}

// Kocher test case 15 is not included.
// The original version can leak secret information even without speculative
//   execution, under the assumption (which we adopt) that all of the function
//   arguments are attacker-controlled. In the original version, the attacker
//   could leak any value in memory by passing the function a pointer to the
//   desired value, which would then be used in a branch calculation, even
//   when executed sequentially.

// We provide a simple main function just so this can compile into a complete
//   binary. Clearly, these inputs will not result in leaked secrets themselves.
int main() {
    case_1(0);
    case_2(0);
    case_3(0);
    case_4(0);
    case_5(0);
    case_6(0);
    case_7(0);
    case_8(0);
    case_9(0);
    case_10(0, 0);
    case_11gcc(0);
    case_11ker(0);
    case_11sub(0);
    case_12(0, 0);
    case_13(0);
    case_14(0);
    return 0;
}
