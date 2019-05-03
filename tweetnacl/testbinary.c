#include "tweetnacl.h"

int main() {
  unsigned char sm[1100], m[1024], sk[64], n[32], pk[64];
  unsigned long long smlen;

  crypto_sign_keypair(pk, sk);
  crypto_sign(sm, &smlen, m, 1024, sk);
  crypto_stream_salsa20(sm, 1100, n, sk);
  crypto_stream_xsalsa20(sm, 1100, n, sk);
  crypto_onetimeauth(sm, m, 1024, sk);
  crypto_onetimeauth_verify(sm, m, 1024, sk);
  crypto_secretbox(sm, m, 1024, n, sk);
  crypto_secretbox_open(sm, m, 1024, n, sk);
  crypto_box(sm, m, 1024, n, pk, sk);
  crypto_box_open(sm, m, 1024, n, pk, sk);

  return 1;
}
