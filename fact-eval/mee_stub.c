#include <stdint.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;
typedef int32_t int32;

void
aesni_cbc_encrypt(
    uint8 *input,
    uint64 input_len,
    uint8* out,
    uint64 out_len,
    uint64 length,
    uint32 key[60], // actually struct AES_KEY
    uint8* iv,
    uint64 iv_len,
    int32 enc){} // really a bool

void
_sha1_update( // sha1_update in e_aes_cbc_hmac_sha1.c
    void* c, // actually struct SHA_CTX
    uint8* data,
    uint64 data_len,
    uint64 length){}

void
SHA1_Final(
    void* a, // unspecified, but SHA_DIGEST_LENGTH
    void* b){} // actually struct SHA_CTX

void
sha1_block_data_order(
    void* a,
    uint8* p,
    uint64 p_len,
    uint32 num){}

int main() {
  return 0;
}
