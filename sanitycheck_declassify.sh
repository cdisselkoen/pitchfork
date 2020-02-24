#!/bin/bash

# watch out! the grep strings have embedded tabs!
objdump -d fact-eval/c_mee.O3 | grep -F '  516c5f:	41 0f b6 54 2d 00    	movzbl 0x0(%r13,%rbp,1),%edx'
objdump -d fact-eval/fact_mee |                   grep -F '401cf3:	43 0f b6 3c 37       	movzbl (%r15,%r14,1),%edi'
objdump -d fact-eval/fact_mee.O3 |                grep -F '401854:	41 3a 3c 0c          	cmp    (%r12,%rcx,1),%dil'
objdump -d fact-eval/c_secretbox.cref.O2 |   grep -F '401d80:	75 23                	jne    401da5 <crypto_secretbox_xsalsa20poly1305_open+0x85>'
objdump -d fact-eval/c_secretbox.asm.O2 |    grep -F '401d80:	75 23                	jne    401da5 <crypto_secretbox_xsalsa20poly1305_open+0x85>'
objdump -d fact-eval/fact_secretbox.cref |        grep -F '403075:	75 02                	jne    403079 <_crypto_secretbox_xsalsa20poly1305_open+0x99>'
objdump -d fact-eval/fact_secretbox.asm |         grep -F '404095:	75 02                	jne    404099 <_crypto_secretbox_xsalsa20poly1305_open+0x99>'
objdump -d fact-eval/fact_secretbox.cref.O2 |     grep -F '4020be:	75 05                	jne    4020c5 <_crypto_secretbox_xsalsa20poly1305_open+0x1a5>'
objdump -d fact-eval/fact_secretbox.asm.O2 |      grep -F '40237e:	75 05                	jne    402385 <_crypto_secretbox_xsalsa20poly1305_open+0x1a5>'
