#include <stdint.h>

// FORCEDINLINE definition from spectector-clang/13.c
#ifdef __MSVC__
#define FORCEDINLINE __forceinline
#else
#define FORCEDINLINE __attribute__((always_inline))
#endif

uint64_t publicarray_size = 16;
uint8_t publicarray[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t publicarray2[512 * 256] = { 20 };

// The attacker's goal in all of these examples is to learn any of the secret data in secretarray
uint64_t secretarray_size = 16;
uint8_t secretarray[16] = { 10,21,32,43,54,65,76,87,98,109,110,121,132,143,154,165 };

// 'volatile' ensures it's actually in memory
volatile uint8_t benignIndex = 0;

// this is mostly used to prevent the compiler from optimizing out certain operations
volatile uint8_t temp = 0;

// gadget that allows (speculatively) writing OOB off of publicarray,
//   so potentially overwriting any attacker-chosen 8-bit location with an attacker-chosen 'val'
FORCEDINLINE static void wrgadget(uint64_t idx, uint8_t val) {
    if (idx < publicarray_size) {
        publicarray[idx] = val;
    }
}

// gadget with the same behaviors as wrgadget(),
//   just formulated slightly differently
FORCEDINLINE static void wrgadget_2(uint64_t idx, uint8_t val) {
    // E.g., this mask is 0xf if publicarray_size is 16.
    const uint64_t publicarray_size_mask = publicarray_size - 1;

    if ((idx & publicarray_size_mask) == idx) {
        publicarray[idx] = val;
    }
}

// gadget that allows (speculatively) writing secret data
//   to an attacker-chosen location (OOB off of secretarray)
FORCEDINLINE static void wrgadget_sec(uint64_t idx) {
    if (idx < secretarray_size) {
        secretarray[idx] = secretarray[0];
    }
}

// gadget that allows (speculatively) writing secret data
//   to locations slightly off the end of secretarray
//   (by having the for loop perform additional iterations)
FORCEDINLINE static void wrgadget_sec_for() {
    for (unsigned i = 0; i < secretarray_size; i++) {
        secretarray[i] = secretarray[0];
    }
}

// In all of these examples, the arguments to the functions are attacker-controlled

void example_1(uint64_t idx, uint8_t val, uint64_t idx2) {
    // E.g., this mask is 0xf if publicarray_size is 16.
    // 'volatile' ensures it's actually in memory.
    volatile uint64_t publicarray_size_mask = publicarray_size - 1;

    // attacker can use this to overwrite publicarray_size_mask
    wrgadget(idx, val);

    // non-speculatively, this code is safe due to the mask applied to idx2.
    // The mask (rather than traditional bounds check) also makes this safe from
    //   Spectre v1.
    // However, by overwriting the mask, the attacker can read OOB off of
    //   publicarray, then observe where in publicarray2 was accessed in order to
    //   leak the secret.
    temp &= publicarray2[publicarray[idx2 & publicarray_size_mask] * 512];
}

void example_2(uint64_t idx) {
    // attacker can use this to write secret data into benignIndex
    wrgadget_sec(idx);

    // non-speculatively, this code is safe because benignIndex is always
    //   in-bounds.
    // However, by writing secret data into benignIndex, the attacker can leak
    //   the secret data through the cache side channel (where in publicarray2
    //   was accessed)
    temp &= publicarray2[benignIndex * 512];
}

void example_3(uint64_t idx, uint8_t mask) {
    // attacker can use this to write secret data into benignIndex
    wrgadget_sec(idx);

    // non-speculatively, this code is safe because no secret data is processed.
    // However, by writing secret data into benignIndex, the attacker can
    //   learn any arbitrary bit of the secret data (by setting 'mask' appropriately)
    if (benignIndex & mask) {
        temp += temp;
    } else {
        temp += 2;
    }
}

void example_4() {
    // attacker can use this to write secret data into benignIndex
    wrgadget_sec_for();

    // leak the same way as in Example 2, just with a different write gadget
    temp &= publicarray2[benignIndex * 512];
}

void example_5(uint64_t idx, uint8_t val, uint64_t idx2) {
    // E.g., this mask is 0xf if publicarray_size is 16.
    // 'volatile' ensures it's actually in memory.
    volatile uint64_t publicarray_size_mask = publicarray_size - 1;

    // attacker can use this to overwrite publicarray_size_mask
    wrgadget_2(idx, val);

    // leak the same way as in Example 1, just with a different write gadget
    temp &= publicarray2[publicarray[idx2 & publicarray_size_mask] * 512];
}

// Provided just so this can compile into a complete binary.
// Clearly, these inputs will not result in leaked secrets themselves.
int main() {
    example_1(0, 0, 0);
    example_2(0);
    example_3(0, 0);
    example_4();
    example_5(0, 0, 0);
    return 0;
}
