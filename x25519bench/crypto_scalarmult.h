#ifndef CRYPTO_SCALARMULT_H
#define CRYPTO_SCALARMULT_H

int crypto_scalarmult_base(unsigned char *q,const unsigned char *n);
int crypto_scalarmult(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);

int crypto_scalarmult_base_lfence(unsigned char *q,const unsigned char *n);
int crypto_scalarmult_lfence(unsigned char *mypublic, const unsigned char *secret, const unsigned char *basepoint);


#endif
