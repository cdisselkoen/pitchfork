	.file	"smult.c"
	.text
	.p2align 4,,15
	.globl	crypto_scalarmult_lfence
	.type	crypto_scalarmult_lfence, @function
crypto_scalarmult_lfence:
.LFB11:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movabsq	$2251799813685247, %rcx
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	xorl	%r15d, %r15d
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	xorl	%r8d, %r8d
	xorl	%r12d, %r12d
	xorl	%r13d, %r13d
	xorl	%r9d, %r9d
	subq	$784, %rsp
	.cfi_def_cfa_offset 840
	movq	(%rsi), %rax
	xorl	%ebp, %ebp
	movq	%rdi, 352(%rsp)
	xorl	%r11d, %r11d
	movq	%rax, 360(%rsp)
	movq	8(%rsi), %rax
	andb	$-8, 360(%rsp)
	movq	%rax, 368(%rsp)
	movq	16(%rsi), %rax
	movq	%rax, 376(%rsp)
	movq	24(%rsi), %rax
	movq	%rax, 384(%rsp)
	shrq	$56, %rax
	andl	$127, %eax
	orl	$64, %eax
	movb	%al, 391(%rsp)
	movq	%rcx, %rax
	andq	(%rdx), %rax
	movq	%rax, %r10
	movq	%rax, 24(%rsp)
	movq	6(%rdx), %rax
	shrq	$3, %rax
	movq	%rax, %rsi
	movq	12(%rdx), %rax
	andq	%rcx, %rsi
	movq	%rsi, 80(%rsp)
	shrq	$6, %rax
	movq	%rax, %rbx
	movq	19(%rdx), %rax
	andq	%rcx, %rbx
	movq	%rbx, 168(%rsp)
	shrq	%rax
	movq	%rax, %rdi
	movq	25(%rdx), %rax
	andq	%rcx, %rdi
	movq	%rdi, 248(%rsp)
	shrq	$4, %rax
	movq	%rax, %rdx
	andq	%rcx, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, 312(%rsp)
	leaq	(%rdx,%rax,2), %rax
	movq	%rax, 176(%rsp)
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	movq	%rax, 320(%rsp)
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %rax
	movq	%rax, 328(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 184(%rsp)
	leaq	391(%rsp), %rax
	movq	%rdx, -24(%rsp)
	leaq	392(%rsp), %rdx
	movq	%r15, 40(%rsp)
	movq	%rsi, %r15
	movq	%rax, 336(%rsp)
	leaq	359(%rsp), %rax
	movq	336(%rsp), %rsi
	movq	%rdx, 56(%rsp)
	leaq	536(%rsp), %rdx
	movq	%rbx, -56(%rsp)
	movq	%rax, 344(%rsp)
	leaq	728(%rsp), %rax
	movl	$1, %ebx
	movq	%r10, -88(%rsp)
	movq	%rdx, 72(%rsp)
	xorl	%r10d, %r10d
	movq	%rax, 208(%rsp)
	leaq	680(%rsp), %rax
	leaq	488(%rsp), %rdx
	movq	%rdi, -40(%rsp)
	movq	%rbx, 88(%rsp)
	xorl	%edi, %edi
	movq	%rax, 216(%rsp)
	leaq	632(%rsp), %rax
	movq	$0, -72(%rsp)
	movq	$0, 8(%rsp)
	movq	$1, 16(%rsp)
	movq	%r8, %rbx
	movq	%rax, -8(%rsp)
	leaq	584(%rsp), %rax
	movq	%r10, 104(%rsp)
	movq	%rax, 200(%rsp)
	leaq	440(%rsp), %rax
	.p2align 4,,10
	.p2align 3
.L3:
  lfence
	movzbl	(%rsi), %esi
	movq	%rax, 224(%rsp)
	movq	208(%rsp), %rax
	movq	%rdx, 232(%rsp)
	movl	$8, 308(%rsp)
	movq	%r11, -120(%rsp)
	movq	%r9, -104(%rsp)
	movq	40(%rsp), %r14
	movb	%sil, 240(%rsp)
	movq	72(%rsp), %rsi
	movq	%rax, 72(%rsp)
	movq	200(%rsp), %rax
	movq	%rsi, 208(%rsp)
	movq	56(%rsp), %rsi
	movq	%rax, 56(%rsp)
	movq	%r8, %rax
	movq	%rsi, 200(%rsp)
	movq	%r15, %rsi
	movq	16(%rsp), %r15
	jmp	.L2
	.p2align 4,,10
	.p2align 3
.L10:
  lfence
	movq	224(%rsp), %r8
	movq	72(%rsp), %rdx
	movq	%r9, 224(%rsp)
	movq	%r8, -8(%rsp)
	movq	208(%rsp), %r8
	movq	%rdx, 208(%rsp)
	movq	56(%rsp), %rdx
	movq	%r8, 72(%rsp)
	movq	200(%rsp), %r8
	movq	%rdx, 200(%rsp)
	movq	216(%rsp), %rdx
	movq	%r8, 56(%rsp)
	movq	232(%rsp), %r8
	movq	%rdx, 232(%rsp)
	movq	%r8, 216(%rsp)
.L2:
	movzbl	240(%rsp), %r8d
	movq	-88(%rsp), %rdx
	movq	%rdx, %r9
	shrb	$7, %r8b
	xorq	%r15, %r9
	movzbl	%r8b, %r8d
	negq	%r8
	andq	%r8, %r9
	movq	%r8, %r11
	xorq	%r9, %r15
	xorq	%rdx, %r9
	movq	-56(%rsp), %rdx
	movq	%r9, 128(%rsp)
	movq	8(%rsp), %r9
	movq	%r15, -88(%rsp)
	movq	%r9, %r15
	xorq	%rsi, %r15
	movq	%r15, %r8
	andq	%r11, %r8
	movq	%r8, %r15
	xorq	%r8, %r9
	movq	%r11, %r8
	xorq	%rsi, %r15
	movq	%rdx, %rsi
	xorq	%r10, %rsi
	movq	%r15, 16(%rsp)
	andq	%r11, %rsi
	movq	-40(%rsp), %r11
	xorq	%rsi, %r10
	movq	%rsi, %r15
	xorq	%rdx, %r15
	movq	%r8, %rdx
	movq	%r11, %rsi
	movq	%r15, 40(%rsp)
	xorq	%rbp, %rsi
	andq	%r8, %rsi
	xorq	%rsi, %rbp
	movq	%rsi, %r15
	movq	-72(%rsp), %rsi
	xorq	%r11, %r15
	movq	-24(%rsp), %r11
	movq	%r15, 48(%rsp)
	movq	%rsi, %r15
	xorq	%r11, %r15
	movq	%r15, %r8
	andq	%rdx, %r8
	xorq	%r8, %rsi
	xorq	%r11, %r8
	movq	88(%rsp), %r11
	movq	%r8, 120(%rsp)
	movq	%r11, %r8
	xorq	%r12, %r8
	andq	%rdx, %r8
	movq	%r8, %r15
	xorq	%r8, %r12
	xorq	%r11, %r15
	movq	-120(%rsp), %r11
	xorq	-104(%rsp), %r11
	movq	%r15, -56(%rsp)
	movq	%rdx, %r15
	movq	%r11, %r8
	movq	-120(%rsp), %r11
	andq	%rdx, %r8
	xorq	%r8, %r11
	xorq	-104(%rsp), %r8
	movq	%r8, 8(%rsp)
	movq	104(%rsp), %r8
	movq	%r15, 104(%rsp)
	movq	%r8, %rdx
	xorq	%rdi, %rdx
	andq	%r15, %rdx
	xorq	%rdx, %rdi
	xorq	%r8, %rdx
	movq	%r14, %r8
	xorq	%r13, %r8
	andq	%r15, %r8
	xorq	%r8, %r14
	xorq	%r8, %r13
	movq	%rbx, %r8
	xorq	%rax, %r8
	andq	%r15, %r8
	movq	232(%rsp), %r15
	xorq	%r8, %rbx
	xorq	%rax, %r8
	movq	-88(%rsp), %rax
	addq	%r12, %rax
	movq	%rax, (%r15)
	movq	%rax, -72(%rsp)
	leaq	(%r11,%r9), %rax
	movq	%rax, 8(%r15)
	movq	%rax, -120(%rsp)
	leaq	(%rdi,%r10), %rax
	movq	%rax, 16(%r15)
	movq	%rax, 88(%rsp)
	leaq	(%r14,%rbp), %rax
	movq	%rax, 24(%r15)
	movq	%rax, 112(%rsp)
	leaq	(%rbx,%rsi), %rax
	movq	%rax, -104(%rsp)
	movq	%rax, 32(%r15)
	movabsq	$18014398509481832, %r15
	addq	-88(%rsp), %r15
	movq	208(%rsp), %rax
	subq	%r12, %r15
	movabsq	$18014398509481976, %r12
	addq	%r12, %r9
	movq	%r15, (%rax)
	movq	%r15, -40(%rsp)
	movq	%r9, %r12
	movq	%rax, %r15
	movq	120(%rsp), %r9
	subq	%r11, %r12
	movq	%r12, 8(%rax)
	movq	%r12, -24(%rsp)
	movabsq	$18014398509481976, %r12
	leaq	(%r10,%r12), %rax
	addq	%r12, %rbp
	addq	%r8, %r9
	movq	%rax, %r11
	movq	128(%rsp), %rax
	subq	%rdi, %r11
	movq	%rbp, %rdi
	movq	%r11, 16(%r15)
	movq	%r11, -88(%rsp)
	leaq	(%rsi,%r12), %r11
	subq	%r14, %rdi
	movq	8(%rsp), %rsi
	addq	16(%rsp), %rsi
	movq	%rdi, %r14
	movq	%rdi, 24(%r15)
	movq	%r11, %rdi
	subq	%rbx, %rdi
	movq	-56(%rsp), %r11
	movabsq	$18014398509481832, %r12
	movq	%rdi, 32(%r15)
	movq	200(%rsp), %r15
	movq	%rdi, %rbp
	movq	%rsi, %r10
	addq	%rax, %r12
	movq	%r11, %rdi
	movq	%rsi, 8(%r15)
	movq	40(%rsp), %rsi
	addq	%rax, %rdi
	movq	%rdi, (%r15)
	movq	%r9, 32(%r15)
	leaq	(%rdx,%rsi), %rbx
	movq	48(%rsp), %rsi
	movq	%rbx, 16(%r15)
	addq	%r13, %rsi
	movq	%rsi, 24(%r15)
	movq	%r12, %r15
	movabsq	$18014398509481976, %r12
	addq	16(%rsp), %r12
	subq	%r11, %r15
	movq	224(%rsp), %r11
	movq	%r15, -56(%rsp)
	movq	%r15, (%r11)
	movq	%r12, %r15
	movabsq	$18014398509481976, %r12
	addq	40(%rsp), %r12
	subq	8(%rsp), %r15
	movq	%r12, %rax
	movabsq	$18014398509481976, %r12
	subq	%rdx, %rax
	movq	%r15, 8(%r11)
	movq	%rax, 16(%rsp)
	movq	%rax, 16(%r11)
	leaq	0(%rbp,%rbp,8), %rax
	addq	48(%rsp), %r12
	movq	%r14, 8(%rsp)
	movq	%r12, %rdx
	movabsq	$18014398509481976, %r12
	addq	120(%rsp), %r12
	subq	%r13, %rdx
	movq	%r11, %r13
	movq	%rbp, 120(%rsp)
	movq	%rdx, 24(%r11)
	movq	%rdx, 48(%rsp)
	movq	%r12, %r11
	subq	%r8, %r11
	movq	-24(%rsp), %r8
	movq	%r11, 32(%r13)
	leaq	0(%rbp,%rax,2), %r13
	movq	-88(%rsp), %rbp
	movq	%r11, 128(%rsp)
	movq	%r13, 40(%rsp)
	leaq	0(%rbp,%rbp,8), %rax
	leaq	0(%rbp,%rax,2), %r11
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %r14
	leaq	(%r8,%r8,8), %rax
	movq	%r11, 136(%rsp)
	leaq	(%r8,%rax,2), %r12
	movq	%r14, 152(%rsp)
	movq	%r12, %rax
	mulq	%r9
	movq	%rax, %r11
	movq	%r13, %rax
	movq	%rdx, %r12
	mulq	%r10
	movq	-40(%rsp), %r13
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%r14, %rax
	adcq	%rdx, %r12
	mulq	%rbx
	addq	%rax, %r11
	movq	136(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	movq	%r11, %r14
	mulq	%r10
	andq	%rcx, %r14
	movq	%r14, 192(%rsp)
	movq	%rax, %r13
	movq	%r8, %rax
	movq	%rdx, %r14
	mulq	%rdi
	addq	%rax, %r13
	movq	40(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%rbx
	addq	%rax, %r13
	movq	136(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%r9
	addq	%rax, %r13
	movq	152(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%rsi
	addq	%r13, %rax
	adcq	%r14, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	movq	%r11, %r13
	movq	%r12, %r14
	addq	%rax, %r13
	movq	-40(%rsp), %rax
	adcq	%rdx, %r14
	movq	%r13, %r11
	andq	%rcx, %r11
	mulq	%rbx
	movq	%r11, 256(%rsp)
	movq	%rax, %r11
	movq	%rbp, %rax
	movq	%rdx, %r12
	mulq	%rdi
	movq	%r8, %rbp
	addq	%rax, %r11
	movq	%r8, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%rax, %r11
	movq	40(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	152(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r9
	addq	%r11, %rax
	movq	%r13, %r11
	adcq	%r12, %rdx
	movq	%r14, %r12
	shrdq	$51, %r14, %r11
	shrq	$51, %r12
	addq	%rax, %r11
	movq	-40(%rsp), %rax
	adcq	%rdx, %r12
	movq	%r11, %r13
	andq	%rcx, %r13
	mulq	%rsi
	movq	%r13, %r8
	movq	%rax, %r13
	movq	8(%rsp), %rax
	movq	%rdx, %r14
	mulq	%rdi
	addq	%rax, %r13
	movq	-88(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%r10
	addq	%rax, %r13
	movq	%rbp, %rax
	adcq	%rdx, %r14
	mulq	%rbx
	addq	%rax, %r13
	movq	40(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%r9
	addq	%r13, %rax
	movq	%r11, %r13
	adcq	%r14, %rdx
	movq	%r12, %r14
	shrdq	$51, %r12, %r13
	shrq	$51, %r14
	addq	%rax, %r13
	movq	%r9, %rax
	adcq	%rdx, %r14
	movq	%r13, %r11
	mulq	-40(%rsp)
	andq	%rcx, %r11
	movq	%r11, 264(%rsp)
	movq	%rdx, %r12
	movq	%rax, %r11
	movq	%rdi, %rax
	mulq	120(%rsp)
	movq	%rax, %rdi
	movq	%rdx, %rbp
	movq	%rsi, %rax
	addq	%r11, %rdi
	adcq	%r12, %rbp
	mulq	-24(%rsp)
	addq	%rax, %rdi
	movq	%r10, %rax
	adcq	%rdx, %rbp
	mulq	8(%rsp)
	addq	%rax, %rdi
	movq	%rbx, %rax
	adcq	%rdx, %rbp
	mulq	-88(%rsp)
	movq	48(%rsp), %r12
	movq	-72(%rsp), %r9
	movq	88(%rsp), %rbx
	addq	%rax, %rdi
	adcq	%rdx, %rbp
	shrdq	$51, %r14, %r13
	shrq	$51, %r14
	movq	%r13, %rax
	movq	%r14, %rdx
	addq	%rdi, %rax
	adcq	%rbp, %rdx
	movq	%rax, %rdi
	movq	%rax, %rsi
	shrdq	$51, %rdx, %rdi
	andq	%rcx, %rsi
	leaq	(%rdi,%rdi,8), %rax
	movq	%rsi, 272(%rsp)
	movq	128(%rsp), %rsi
	leaq	(%rdi,%rax,2), %rax
	addq	192(%rsp), %rax
	movq	16(%rsp), %rdi
	movq	%rax, %r14
	shrq	$51, %rax
	addq	256(%rsp), %rax
	andq	%rcx, %r14
	movq	%r14, 280(%rsp)
	movq	-120(%rsp), %r14
	movq	%rax, %r13
	shrq	$51, %rax
	leaq	(%rax,%r8), %rbp
	leaq	(%rsi,%rsi,8), %rax
	andq	%rcx, %r13
	movq	%r13, 256(%rsp)
	movq	-56(%rsp), %r13
	leaq	(%rsi,%rax,2), %rsi
	leaq	(%rdi,%rdi,8), %rax
	movq	%rbp, 192(%rsp)
	movq	112(%rsp), %rbp
	leaq	(%rdi,%rax,2), %r8
	leaq	(%r12,%r12,8), %rax
	leaq	(%r12,%rax,2), %rdi
	leaq	(%r15,%r15,8), %rax
	leaq	(%r15,%rax,2), %r10
	movq	%r10, %rax
	movq	-104(%rsp), %r10
	mulq	%r10
	movq	%rax, %r11
	movq	%r14, %rax
	movq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	mulq	%r9
	addq	%rax, %r11
	movq	%rbx, %rax
	adcq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%rbp, %rax
	adcq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%r11, %rax
	adcq	%rdx, %r12
	andq	%rcx, %rax
	movq	%rax, 288(%rsp)
	movq	%r13, %rax
	mulq	%r14
	movq	%rax, %r13
	movq	%r9, %rax
	movq	%rdx, %r14
	mulq	%r15
	addq	%rax, %r13
	movq	%rbx, %rax
	adcq	%rdx, %r14
	mulq	%rsi
	addq	%rax, %r13
	movq	%r8, %rax
	movq	%rbp, %r8
	adcq	%rdx, %r14
	mulq	%r10
	addq	%rax, %r13
	movq	%rbp, %rax
	adcq	%rdx, %r14
	mulq	%rdi
	addq	%r13, %rax
	movq	%r11, %r13
	adcq	%r14, %rdx
	movq	%r12, %r14
	shrdq	$51, %r12, %r13
	shrq	$51, %r14
	movq	%r13, %r9
	movq	%r14, %r10
	movq	%rbx, %r14
	addq	%rax, %r9
	movq	-56(%rsp), %rax
	adcq	%rdx, %r10
	movq	%r9, %r13
	andq	%rcx, %r13
	mulq	%rbx
	movq	%rax, %r11
	movq	%rdx, %r12
	movq	-72(%rsp), %rax
	mulq	16(%rsp)
	addq	%rax, %r11
	movq	-120(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r15
	addq	%rax, %r11
	movq	%r8, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	%rdi, %rax
	adcq	%rdx, %r12
	mulq	-104(%rsp)
	movq	%rax, %rdi
	movq	%rdx, %rbp
	movq	%r9, %rax
	addq	%r11, %rdi
	movq	%r10, %rdx
	adcq	%r12, %rbp
	shrq	$51, %rdx
	shrdq	$51, %r10, %rax
	movq	%rdx, %r12
	movq	%rax, %r11
	movq	-56(%rsp), %rax
	addq	%rdi, %r11
	adcq	%rbp, %r12
	movq	%r11, %rbx
	movq	%r8, %rbp
	mulq	%r8
	andq	%rcx, %rbx
	movq	%r12, %rdi
	movq	%rax, %r9
	movq	%rdx, %r10
	movq	-72(%rsp), %rax
	mulq	48(%rsp)
	addq	%rax, %r9
	movq	-120(%rsp), %rax
	adcq	%rdx, %r10
	mulq	16(%rsp)
	addq	%rax, %r9
	movq	%r14, %rax
	adcq	%rdx, %r10
	mulq	%r15
	addq	%rax, %r9
	movq	%rsi, %rax
	movq	%r11, %rsi
	adcq	%rdx, %r10
	mulq	-104(%rsp)
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrq	$51, %rdi
	shrdq	$51, %r12, %rsi
	movq	%rdi, %r12
	movq	%rsi, %r11
	addq	%rax, %r11
	movq	-56(%rsp), %rax
	adcq	%rdx, %r12
	movq	%r11, %rdx
	andq	%rcx, %rdx
	movq	%rdx, %r8
	mulq	-104(%rsp)
	movq	%rax, %r9
	movq	%rdx, %r10
	movq	128(%rsp), %rax
	mulq	-72(%rsp)
	addq	%rax, %r9
	movq	%r15, %rax
	adcq	%rdx, %r10
	mulq	%rbp
	addq	%rax, %r9
	movq	48(%rsp), %rax
	movq	280(%rsp), %r15
	adcq	%rdx, %r10
	mulq	-120(%rsp)
	addq	%rax, %r9
	movq	16(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r14
	movq	256(%rsp), %r14
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	movq	%r11, %r10
	movq	%r12, %r11
	movq	272(%rsp), %r12
	addq	%rax, %r10
	adcq	%rdx, %r11
	movq	%r10, %rdx
	shrdq	$51, %r11, %r10
	andq	%rcx, %rdx
	movq	%r12, %rbp
	leaq	(%r10,%r10,8), %rax
	addq	%rdx, %rbp
	leaq	(%r10,%rax,2), %rax
	addq	288(%rsp), %rax
	movq	%rax, %r10
	shrq	$51, %rax
	andq	%rcx, %r10
	addq	%rax, %r13
	leaq	(%r15,%r10), %r11
	movq	%r13, %rax
	shrq	$51, %r13
	andq	%rcx, %rax
	addq	%rbx, %r13
	movq	%r11, 16(%rsp)
	movabsq	$18014398509481832, %r11
	movq	%rax, %r9
	addq	%r11, %r15
	movabsq	$18014398509481976, %r11
	leaq	(%r14,%r9), %rbx
	subq	%r10, %r15
	movq	192(%rsp), %rax
	movq	%r15, 48(%rsp)
	leaq	(%r11,%r14), %r15
	subq	%r9, %r15
	movq	%r11, %r9
	addq	192(%rsp), %r9
	leaq	(%rax,%r13), %rsi
	movq	264(%rsp), %rax
	movq	%r15, 128(%rsp)
	movq	%r9, %r10
	leaq	(%rax,%r8), %rdi
	leaq	(%r11,%rax), %r15
	subq	%r13, %r10
	movq	%r10, %r13
	movq	%r11, %r10
	movq	16(%rsp), %r11
	addq	%r12, %r10
	subq	%r8, %r15
	movq	%r10, %rax
	subq	%rdx, %rax
	leaq	(%rbx,%rbx), %rdx
	leaq	(%r11,%r11), %r14
	movq	%rax, -56(%rsp)
	movq	%rdx, 16(%rsp)
	leaq	0(%rbp,%rbp,8), %rdx
	leaq	0(%rbp,%rdx,2), %rax
	leaq	(%rax,%rax), %r8
	movq	%rax, 264(%rsp)
	movq	%r11, %rax
	mulq	%r11
	movq	%rax, %r11
	movq	%r8, %rax
	movq	%rdx, %r12
	mulq	%rbx
	addq	%rax, %r11
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %r12
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%rdi
	addq	%rax, %r11
	leaq	(%rdi,%rdi,8), %rax
	adcq	%rdx, %r12
	movq	%r11, %rdx
	leaq	(%rdi,%rax,2), %r10
	andq	%rcx, %rdx
	movq	%rdx, 192(%rsp)
	movq	%r10, %rax
	mulq	%rdi
	movq	%rax, %r9
	movq	%rbx, %rax
	movq	%rdx, %r10
	mulq	%r14
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%r9, %rax
	movq	%r11, %r9
	adcq	%r10, %rdx
	movq	%r12, %r10
	shrdq	$51, %r12, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	%rbx, %rax
	adcq	%rdx, %r10
	movq	%r9, %rdx
	andq	%rcx, %rdx
	movq	%rdx, 256(%rsp)
	mulq	%rbx
	movq	16(%rsp), %rbx
	movq	%rax, %r11
	movq	%r8, %rax
	movq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%r14, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	%rdi, %rax
	adcq	%rdx, %r10
	movq	%r9, %r8
	mulq	%r14
	andq	%rcx, %r8
	movq	%rax, %r11
	movq	264(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rbp
	addq	%rax, %r11
	movq	%rbx, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	movq	%r9, %r11
	movq	%r10, %r12
	addq	%rax, %r11
	movq	%rbx, %rax
	adcq	%rdx, %r12
	movq	%r11, 16(%rsp)
	mulq	%rdi
	movq	%rax, %r9
	movq	%rsi, %rax
	movq	%rdx, %r10
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r14, %rax
	addq	%r9, %rsi
	adcq	%r10, %rdi
	movq	48(%rsp), %r10
	mulq	%rbp
	movq	128(%rsp), %rbp
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	movq	%rsi, %rax
	shrdq	$51, %r12, %r11
	movq	%rdi, %rdx
	shrq	$51, %r12
	movq	-56(%rsp), %rdi
	addq	%r11, %rax
	adcq	%r12, %rdx
	movq	%rax, 264(%rsp)
	shrdq	$51, %rdx, %rax
	movq	%rax, %rsi
	leaq	(%rax,%rax,8), %rax
	leaq	(%rsi,%rax,2), %rdx
	addq	192(%rsp), %rdx
	leaq	(%r10,%r10), %rsi
	movq	%rdx, 192(%rsp)
	shrq	$51, %rdx
	movq	%rdx, %rax
	addq	256(%rsp), %rax
	movq	%rax, 256(%rsp)
	shrq	$51, %rax
	leaq	(%rax,%r8), %rbx
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %r8
	movq	%r10, %rax
	movq	%rbx, 272(%rsp)
	mulq	%r10
	leaq	(%rbp,%rbp), %rbx
	leaq	(%r8,%r8), %rdi
	movq	%rax, %r11
	movq	%rbp, %rax
	movq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	leaq	0(%r13,%r13,8), %rax
	adcq	%rdx, %r12
	leaq	0(%r13,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r15
	addq	%rax, %r11
	leaq	(%r15,%r15,8), %rax
	adcq	%rdx, %r12
	movq	%r11, %r10
	leaq	(%r15,%rax,2), %r14
	andq	%rcx, %r10
	movq	%r10, 48(%rsp)
	movq	%r14, %rax
	mulq	%r15
	movq	%rax, %r9
	movq	%rbp, %rax
	movq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%rdi, %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%r9, %rax
	adcq	%r10, %rdx
	movq	%r11, %r10
	movq	%r12, %r11
	shrdq	$51, %r12, %r10
	shrq	$51, %r11
	movq	%r10, %r9
	movq	%r11, %r10
	addq	%rax, %r9
	movq	%rbp, %rax
	adcq	%rdx, %r10
	movq	%r9, %r14
	mulq	%rbp
	andq	%rcx, %r14
	movq	%rax, %r11
	movq	%rdi, %rax
	movq	%rdx, %r12
	mulq	%r15
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	mulq	%r13
	addq	%r11, %rax
	movq	%r10, %r11
	movq	%r9, %r10
	adcq	%r12, %rdx
	shrdq	$51, %r11, %r10
	shrq	$51, %r11
	movq	%r11, %r12
	movq	%r10, %r11
	addq	%rax, %r11
	movq	%r11, %rax
	adcq	%rdx, %r12
	andq	%rcx, %rax
	movq	%rax, 128(%rsp)
	movq	%r15, %rax
	movq	-56(%rsp), %rdi
	mulq	%rsi
	movq	%rax, %r9
	movq	%r8, %rax
	movq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	%r13, %rax
	adcq	%rdx, %r10
	mulq	%rbx
	addq	%r9, %rax
	adcq	%r10, %rdx
	movq	%r11, %r10
	movq	%r12, %r11
	shrdq	$51, %r12, %r10
	shrq	$51, %r11
	movq	%r10, %r9
	movq	%r11, %r10
	addq	%rax, %r9
	movq	%r15, %rax
	adcq	%rdx, %r10
	movq	%r9, %rbp
	mulq	%rbx
	andq	%rcx, %rbp
	movq	%rax, %r11
	movq	%r13, %rax
	movq	%rdx, %r12
	mulq	%r13
	addq	%rax, %r11
	movq	%rdi, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	movq	328(%rsp), %r11
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	adcq	%rdx, %r10
	movq	%r9, %rax
	movq	%r9, %rbx
	shrdq	$51, %r10, %rax
	andq	%rcx, %rbx
	movq	24(%rsp), %r10
	movq	176(%rsp), %r9
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rsi
	movq	320(%rsp), %rax
	addq	48(%rsp), %rsi
	mulq	%rbx
	movq	%rsi, %r15
	shrq	$51, %rsi
	addq	%r14, %rsi
	andq	%rcx, %r15
	movq	%r15, %r8
	movq	%rsi, %r15
	shrq	$51, %rsi
	movq	%rax, %r13
	movq	%r11, %rax
	movq	%rdx, %r14
	mulq	%rbp
	addq	128(%rsp), %rsi
	andq	%rcx, %r15
	movq	%r15, %rdi
	addq	%rax, %r13
	movq	%r10, %rax
	adcq	%rdx, %r14
	mulq	%r8
	addq	%rax, %r13
	movq	%r9, %rax
	adcq	%rdx, %r14
	mulq	%r15
	addq	%rax, %r13
	movq	184(%rsp), %rax
	adcq	%rdx, %r14
	mulq	%rsi
	addq	%rax, %r13
	movq	%r11, %rax
	adcq	%rdx, %r14
	movq	%r13, %r15
	mulq	%rbx
	andq	%rcx, %r15
	movq	%rax, %r11
	movq	184(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rbp
	addq	%rax, %r11
	movq	80(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%r10, %rax
	adcq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r14, %r13
	shrq	$51, %r14
	movq	%r13, %r11
	movq	%r14, %r12
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	movq	%r11, %r14
	mulq	%rbp
	andq	%rcx, %r14
	movq	%rax, %r9
	movq	184(%rsp), %rax
	movq	%rdx, %r10
	mulq	%rbx
	addq	%rax, %r9
	movq	168(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r8
	addq	%rax, %r9
	movq	80(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	24(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%r9, %rax
	movq	%r11, %r9
	adcq	%r10, %rdx
	movq	%r12, %r10
	shrdq	$51, %r12, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	24(%rsp), %rax
	adcq	%rdx, %r10
	movq	%r9, %r13
	andq	%rcx, %r13
	mulq	%rbp
	movq	%rax, %r11
	movq	176(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rbx
	addq	%rax, %r11
	movq	248(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	168(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	80(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	movq	%r9, %r11
	movq	%r10, %r12
	addq	%rax, %r11
	movq	%rbx, %rax
	adcq	%rdx, %r12
	movq	%r11, 48(%rsp)
	mulq	24(%rsp)
	movq	%rax, %r9
	movq	%rdx, %r10
	movq	%rbp, %rax
	mulq	80(%rsp)
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	312(%rsp)
	addq	%rax, %r9
	movq	%rdi, %rax
	adcq	%rdx, %r10
	mulq	248(%rsp)
	movq	%rax, %rdi
	movq	%rdx, %rbp
	movq	%rsi, %rax
	addq	%r9, %rdi
	adcq	%r10, %rbp
	mulq	168(%rsp)
	addq	%rax, %rdi
	movq	%r11, %rax
	adcq	%rdx, %rbp
	movq	%r12, %rdx
	shrdq	$51, %r12, %rax
	shrq	$51, %rdx
	movq	-120(%rsp), %r12
	addq	%rdi, %rax
	adcq	%rbp, %rdx
	movq	%rax, 128(%rsp)
	shrdq	$51, %rdx, %rax
	leaq	(%r12,%r12), %rbp
	movq	%rax, %rdi
	leaq	(%rax,%rax,8), %rax
	leaq	(%rdi,%rax,2), %r8
	movq	-104(%rsp), %rdi
	leaq	(%r8,%r15), %rax
	movq	%rax, %r10
	movq	%rax, 280(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	shrq	$51, %r10
	leaq	(%r10,%r14), %r10
	movq	-72(%rsp), %r14
	leaq	(%rdi,%rax,2), %r11
	movq	%r10, %rdx
	movq	%r10, 288(%rsp)
	leaq	(%r11,%r11), %r8
	shrq	$51, %rdx
	leaq	(%r14,%r14), %rbx
	leaq	(%rdx,%r13), %r15
	movq	%r15, 296(%rsp)
	movq	88(%rsp), %r15
	movq	112(%rsp), %r13
	leaq	(%r15,%r15,8), %rax
	leaq	(%r15,%rax,2), %rsi
	addq	%rsi, %rsi
	movq	%rsi, %rax
	mulq	%r13
	movq	%rax, %rsi
	movq	%r14, %rax
	movq	%rdx, %rdi
	mulq	%r14
	addq	%rax, %rsi
	movq	%r12, %rax
	adcq	%rdx, %rdi
	mulq	%r8
	addq	%rax, %rsi
	leaq	0(%r13,%r13,8), %rax
	movq	%rsi, -72(%rsp)
	movq	%rsi, %r14
	adcq	%rdx, %rdi
	leaq	0(%r13,%rax,2), %rsi
	andq	%rcx, %r14
	movq	%rdi, -64(%rsp)
	movq	-64(%rsp), %rdi
	movq	%rsi, %rax
	movq	-72(%rsp), %rsi
	mulq	%r13
	movq	%rax, %r9
	movq	%r12, %rax
	movq	%rdx, %r10
	mulq	%rbx
	addq	%rax, %r9
	movq	%r15, %rax
	adcq	%rdx, %r10
	mulq	%r8
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rax, %rsi
	movq	%r15, %rax
	adcq	%rdx, %rdi
	movq	%rsi, -72(%rsp)
	andq	%rcx, %rsi
	mulq	%rbx
	movq	%rdi, -64(%rsp)
	movq	-120(%rsp), %rdi
	movq	%rsi, %r12
	movq	-72(%rsp), %rsi
	movq	%rax, %r9
	movq	%rdi, %rax
	movq	%rdx, %r10
	mulq	%rdi
	movq	-64(%rsp), %rdi
	addq	%rax, %r9
	movq	%r8, %rax
	movq	%r13, %r8
	adcq	%rdx, %r10
	mulq	%r13
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rax, %rsi
	movq	%r8, %rax
	adcq	%rdx, %rdi
	movq	%rsi, %r13
	movq	%rsi, -120(%rsp)
	mulq	%rbx
	andq	%rcx, %r13
	movq	-120(%rsp), %rsi
	movq	%rdi, -112(%rsp)
	movq	-112(%rsp), %rdi
	movq	%rax, %r9
	movq	%r15, %rax
	movq	%rdx, %r10
	mulq	%rbp
	addq	%rax, %r9
	movq	%r11, %rax
	movq	-104(%rsp), %r11
	adcq	%rdx, %r10
	mulq	%r11
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rax, %rsi
	movq	%r11, %rax
	adcq	%rdx, %rdi
	movq	%rsi, -104(%rsp)
	mulq	%rbx
	movq	%rdi, -96(%rsp)
	movq	%rsi, %rdi
	andq	%rcx, %rdi
	movq	-104(%rsp), %rsi
	movq	%rdi, -120(%rsp)
	movq	-96(%rsp), %rdi
	movq	%rax, %r9
	movq	%r8, %rax
	movq	%rdx, %r10
	mulq	%rbp
	movq	8(%rsp), %r8
	addq	%rax, %r9
	movq	%r15, %rax
	adcq	%rdx, %r10
	mulq	%r15
	addq	%r9, %rax
	movq	-24(%rsp), %r9
	adcq	%r10, %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	leaq	(%r9,%r9), %rbp
	movq	%rsi, %r10
	movq	%rdi, %r11
	addq	%rax, %r10
	adcq	%rdx, %r11
	movq	%r10, %r15
	shrdq	$51, %r11, %r10
	andq	%rcx, %r15
	movq	-88(%rsp), %r11
	leaq	(%r10,%r10,8), %rax
	leaq	(%r10,%rax,2), %rax
	addq	%rax, %r14
	movq	%r14, %rbx
	shrq	$51, %r14
	addq	%r14, %r12
	andq	%rcx, %rbx
	movq	%r12, %r14
	shrq	$51, %r12
	movq	%rbx, -104(%rsp)
	addq	%r12, %r13
	movq	40(%rsp), %r12
	movq	-40(%rsp), %rbx
	andq	%rcx, %r14
	movq	%r13, -56(%rsp)
	movq	%r14, -72(%rsp)
	leaq	(%r12,%r12), %rdi
	movq	136(%rsp), %r12
	leaq	(%rbx,%rbx), %rsi
	addq	%r12, %r12
	movq	%r12, %rax
	mulq	%r8
	movq	%rax, %r13
	movq	%rbx, %rax
	movq	%rdx, %r14
	mulq	%rbx
	addq	%rax, %r13
	movq	%r9, %rax
	adcq	%rdx, %r14
	mulq	%rdi
	addq	%rax, %r13
	movq	%r9, %rax
	adcq	%rdx, %r14
	movq	%r13, %r12
	mulq	%rsi
	movq	%r12, %rbx
	movq	%r14, %r13
	andq	%rcx, %rbx
	movq	%r13, %r14
	movq	%r12, %r13
	movq	%rax, %r9
	movq	152(%rsp), %rax
	movq	%rdx, %r10
	mulq	%r8
	addq	%rax, %r9
	movq	%r11, %rax
	adcq	%rdx, %r10
	mulq	%rdi
	addq	%r9, %rax
	movq	-24(%rsp), %r9
	adcq	%r10, %rdx
	shrdq	$51, %r14, %r13
	shrq	$51, %r14
	addq	%rax, %r13
	movq	%r11, %rax
	adcq	%rdx, %r14
	movq	%r13, %r12
	mulq	%rsi
	andq	%rcx, %r12
	movq	%r12, %r8
	movq	%rax, %r11
	movq	%r9, %rax
	movq	%rdx, %r12
	mulq	%r9
	movq	8(%rsp), %r9
	addq	%rax, %r11
	movq	%rdi, %rax
	adcq	%rdx, %r12
	mulq	%r9
	addq	%r11, %rax
	adcq	%r12, %rdx
	movq	%r13, %r12
	movq	%r14, %r13
	shrdq	$51, %r14, %r12
	shrq	$51, %r13
	movq	%r12, %r11
	movq	%r13, %r12
	movq	-88(%rsp), %r13
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	movq	%r11, %rdi
	mulq	%rsi
	andq	%rcx, %rdi
	movq	%rax, %r9
	movq	%r13, %rax
	movq	%rdx, %r10
	mulq	%rbp
	addq	%rax, %r9
	movq	40(%rsp), %rax
	adcq	%rdx, %r10
	mulq	120(%rsp)
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	movq	%r11, %r9
	movq	%r12, %r10
	addq	%rax, %r9
	movq	120(%rsp), %rax
	adcq	%rdx, %r10
	movq	%r9, %r12
	andq	%rcx, %r12
	mulq	%rsi
	movq	%r12, %r14
	movq	%rax, %r11
	movq	8(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rbp
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	mulq	%r13
	addq	%r11, %rax
	movq	-72(%rsp), %r11
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rax
	adcq	%r10, %rdx
	movq	%rax, %r12
	shrdq	$51, %rdx, %rax
	andq	%rcx, %r12
	leaq	(%rax,%rax,8), %rdx
	movq	%r12, -88(%rsp)
	leaq	(%rax,%rdx,2), %r13
	leaq	(%r12,%r12,8), %rax
	addq	%rbx, %r13
	movq	%r13, %rbp
	shrq	$51, %r13
	addq	%r8, %r13
	andq	%rcx, %rbp
	movq	%r13, %rbx
	shrq	$51, %r13
	addq	%rdi, %r13
	leaq	(%r12,%rax,2), %rdi
	andq	%rcx, %rbx
	leaq	0(%r13,%r13,8), %rax
	leaq	0(%r13,%rax,2), %rsi
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %r8
	movq	-104(%rsp), %rax
	mulq	%rbp
	movq	%rax, %r9
	movq	%r11, %rax
	movq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	-56(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r8
	addq	%rax, %r9
	leaq	(%rbx,%rbx,8), %rax
	adcq	%rdx, %r10
	leaq	(%rbx,%rax,2), %rax
	mulq	%r15
	addq	%rax, %r9
	movq	-120(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r11, %rax
	adcq	%rdx, %r10
	movq	%r9, %r12
	mulq	%rbp
	andq	%rcx, %r12
	movq	%r12, 8(%rsp)
	movq	%rax, %r11
	movq	-120(%rsp), %rax
	movq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	-104(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rbx
	addq	%rax, %r11
	movq	-56(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%rsi, %rax
	movq	-104(%rsp), %rsi
	adcq	%rdx, %r12
	mulq	%r15
	addq	%r11, %rax
	movq	%r9, %r11
	adcq	%r12, %rdx
	movq	%r10, %r12
	shrdq	$51, %r10, %r11
	shrq	$51, %r12
	addq	%rax, %r11
	movq	-120(%rsp), %rax
	adcq	%rdx, %r12
	movq	%r11, %rdx
	andq	%rcx, %rdx
	movq	%rdx, -40(%rsp)
	mulq	%rdi
	movq	%rax, %r9
	movq	%r8, %rax
	movq	%rdx, %r10
	mulq	%r15
	addq	%rax, %r9
	movq	-56(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rbp
	addq	%rax, %r9
	movq	-72(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rbx
	addq	%rax, %r9
	movq	%rsi, %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	movq	%r11, -24(%rsp)
	andq	%rcx, %r11
	mulq	%r14
	movq	%r11, %r8
	movq	%r12, -16(%rsp)
	movq	-24(%rsp), %r11
	movq	-16(%rsp), %r12
	movq	%rax, %r9
	movq	%rdi, %rax
	movq	%rdx, %r10
	mulq	%r15
	movq	%rax, %rsi
	movq	-120(%rsp), %rax
	movq	%rdx, %rdi
	addq	%r9, %rsi
	adcq	%r10, %rdi
	mulq	%rbp
	addq	%rax, %rsi
	movq	-56(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%rbx
	addq	%rax, %rsi
	movq	-72(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r13
	addq	%rax, %rsi
	movq	%rbp, %rax
	adcq	%rdx, %rdi
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	addq	%r11, %rsi
	movq	-104(%rsp), %r11
	adcq	%r12, %rdi
	movq	-120(%rsp), %r12
	movq	%rsi, -24(%rsp)
	mulq	%r15
	movq	%rax, %r9
	movq	%rdx, %r10
	movq	%r11, %rax
	mulq	-88(%rsp)
	addq	%rax, %r9
	movq	-72(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r14
	addq	%rax, %r9
	movq	%r12, %rax
	adcq	%rdx, %r10
	mulq	%rbx
	addq	%rax, %r9
	movq	-56(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rax
	adcq	%rdi, %rdx
	movq	%rax, %rsi
	movq	%rax, 40(%rsp)
	shrdq	$51, %rdx, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	movq	%rax, %rdi
	addq	8(%rsp), %rdi
	movabsq	$18014398509481832, %rax
	movq	%rdi, 88(%rsp)
	shrq	$51, %rdi
	movq	%rdi, %r9
	leaq	(%rax,%r11), %rdi
	movabsq	$18014398509481976, %rax
	addq	-72(%rsp), %rax
	addq	-40(%rsp), %r9
	subq	%rbp, %rdi
	subq	%rbx, %rax
	movq	%r9, %r10
	movq	%r9, 112(%rsp)
	movq	%rax, %rbx
	movabsq	$18014398509481976, %rax
	addq	-56(%rsp), %rax
	shrq	$51, %r10
	addq	%r8, %r10
	movq	%r10, 120(%rsp)
	movq	%rax, %rbp
	subq	%r13, %rbp
	movabsq	$18014398509481976, %r13
	addq	%r12, %r13
	movq	-120(%rsp), %r12
	movq	%rbp, 8(%rsp)
	subq	%r14, %r13
	movq	%r13, %r14
	movabsq	$18014398509481976, %r13
	leaq	(%r15,%r13), %rax
	subq	-88(%rsp), %rax
	movq	%rdi, -88(%rsp)
	movq	%r14, -40(%rsp)
	movq	%rax, %r8
	movl	$121665, %eax
	mulq	%rdi
	movq	%rax, %r11
	movq	%rax, %rsi
	movl	$121665, %eax
	movq	%rdx, %rdi
	shrdq	$51, %rdx, %rsi
	mulq	%rbx
	shrq	$51, %rdi
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	movq	%rsi, %rax
	movq	%rsi, 136(%rsp)
	shrdq	$51, %rdi, %rax
	movq	%rdi, %rdx
	movq	%rdi, 144(%rsp)
	movq	136(%rsp), %rsi
	shrq	$51, %rdx
	movq	%rax, %r9
	movl	$121665, %eax
	movq	%rdx, %r10
	mulq	%rbp
	addq	%r9, %rax
	adcq	%r10, %rdx
	movq	%rax, %rdi
	shrdq	$51, %rdx, %rax
	shrq	$51, %rdx
	movq	%rax, %r9
	movl	$121665, %eax
	movq	%rdx, %r10
	mulq	%r14
	addq	%rax, %r9
	movl	$121665, %eax
	adcq	%rdx, %r10
	movq	%r9, %r13
	mulq	%r8
	movq	%r10, %r14
	shrdq	$51, %r10, %r13
	shrq	$51, %r14
	addq	%r13, %rax
	movq	%rax, 152(%rsp)
	movq	%rax, %r13
	movq	152(%rsp), %rax
	adcq	%r14, %rdx
	andq	%rcx, %rdi
	addq	-56(%rsp), %rdi
	shrdq	$51, %rdx, %r13
	andq	%rcx, %rax
	movq	%rdx, 160(%rsp)
	andq	%rcx, %r11
	addq	%rax, %r15
	addq	-104(%rsp), %r11
	leaq	0(%r13,%r13,8), %rdx
	leaq	(%r15,%r15,8), %rax
	andq	%rcx, %r9
	andq	%rcx, %rsi
	leaq	(%r9,%r12), %rbp
	addq	-72(%rsp), %rsi
	leaq	0(%r13,%rdx,2), %rdx
	leaq	(%r15,%rax,2), %r14
	leaq	(%rdi,%rdi,8), %rax
	movq	-88(%rsp), %r9
	leaq	(%rdx,%r11), %r13
	leaq	(%rdi,%rax,2), %r12
	leaq	0(%rbp,%rbp,8), %rax
	movq	%r13, -104(%rsp)
	leaq	0(%rbp,%rax,2), %r13
	leaq	(%rsi,%rsi,8), %rax
	movq	%r12, %r10
	movq	%r10, -72(%rsp)
	leaq	(%rsi,%rax,2), %r12
	movq	%r12, %rax
	mulq	%r8
	movq	%rax, %r11
	movq	-40(%rsp), %rax
	movq	%rdx, %r12
	mulq	%r10
	addq	%rax, %r11
	movq	8(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r13
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	mulq	-104(%rsp)
	addq	%rax, %r11
	movq	%rbx, %rax
	adcq	%rdx, %r12
	mulq	%r14
	addq	%rax, %r11
	movq	%r11, %rax
	adcq	%rdx, %r12
	andq	%rcx, %rax
	movq	%rax, -120(%rsp)
	movq	%r9, %rax
	mulq	%rsi
	movq	%rax, %r9
	movq	-72(%rsp), %rax
	movq	%rdx, %r10
	mulq	%r8
	addq	%rax, %r9
	movq	-40(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%rax, %r9
	movq	-104(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rbx
	addq	%rax, %r9
	movq	8(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r14
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	movq	%r11, %r9
	movq	%r12, %r10
	addq	%rax, %r9
	movq	-88(%rsp), %rax
	adcq	%rdx, %r10
	movq	%r9, %r12
	andq	%rcx, %r12
	mulq	%rdi
	movq	%r12, -56(%rsp)
	movq	%rax, %r11
	movq	%rbx, %rax
	movq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	8(%rsp), %rax
	adcq	%rdx, %r12
	mulq	-104(%rsp)
	addq	%rax, %r11
	movq	-40(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r14
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	%rbx, %rax
	adcq	%rdx, %r10
	movq	%r9, %r12
	mulq	%rdi
	andq	%rcx, %r12
	movq	%r10, -64(%rsp)
	movq	%r12, %r13
	movq	%rax, %r11
	movq	8(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rsi
	addq	%rax, %r11
	movq	-88(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rbp
	addq	%rax, %r11
	movq	-40(%rsp), %rax
	adcq	%rdx, %r12
	mulq	-104(%rsp)
	addq	%rax, %r11
	movq	%r14, %rax
	adcq	%rdx, %r12
	mulq	%r8
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	-40(%rsp), %rax
	adcq	%rdx, %r10
	movq	%r9, %r14
	mulq	%rsi
	movq	%rax, %r11
	movq	8(%rsp), %rax
	movq	%rdx, %r12
	mulq	%rdi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%rbx, %rax
	addq	%r11, %rsi
	adcq	%r12, %rdi
	mulq	%rbp
	movq	56(%rsp), %rbp
	addq	%rax, %rsi
	movq	-88(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r15
	movq	88(%rsp), %r15
	addq	%rax, %rsi
	movq	-104(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r8
	movq	112(%rsp), %r8
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	movq	256(%rsp), %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rsi
	adcq	%r10, %rdi
	movq	%rsi, %rbx
	movq	104(%rsp), %r10
	shrdq	$51, %rdi, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %r12
	addq	-120(%rsp), %r12
	movq	192(%rsp), %rsi
	movq	%r12, %r11
	shrq	$51, %r11
	addq	-56(%rsp), %r11
	movq	%r11, %rdi
	shrq	$51, %rdi
	addq	%r13, %rdi
	movq	%r10, %r13
	andq	%rcx, %r13
	movq	%r13, %rax
	movq	%rsi, %r13
	andq	%rcx, %rsi
	xorq	%r15, %r13
	andq	%rcx, %r15
	movq	%r13, %r9
	movq	216(%rsp), %r13
	andq	%rax, %r9
	xorq	%r9, %rsi
	xorq	%r9, %r15
	movq	%rsi, 0(%rbp)
	movq	%rsi, -88(%rsp)
	movq	%rdx, %rsi
	xorq	%r8, %rsi
	andq	%rcx, %rdx
	andq	%rcx, %r8
	andq	%rax, %rsi
	movq	%r15, 0(%r13)
	xorq	%rsi, %r8
	xorq	%rdx, %rsi
	movq	%rbp, %rdx
	movq	%rsi, 8(%rbp)
	movq	272(%rsp), %rbp
	movq	%r8, 8(%r13)
	movq	%r8, 8(%rsp)
	movq	120(%rsp), %r9
	movq	%rbp, %r8
	xorq	%r9, %r8
	andq	%r10, %r8
	movq	%r9, %r10
	movq	%rdx, %r9
	xorq	%r8, %r10
	xorq	%rbp, %r8
	movq	-24(%rsp), %rbp
	movq	%r8, 16(%rdx)
	movq	%r8, -56(%rsp)
	movq	16(%rsp), %r8
	movq	%r10, 16(%r13)
	movq	%r8, %rdx
	andq	%rcx, %r8
	xorq	%rbp, %rdx
	andq	%rcx, %rbp
	andq	%rax, %rdx
	xorq	%rdx, %r8
	xorq	%rdx, %rbp
	movq	%r8, %rdx
	movq	%r8, -40(%rsp)
	movq	%rbp, 24(%r13)
	movq	%rdx, 24(%r9)
	movq	264(%rsp), %r9
	movq	40(%rsp), %rdx
	movq	%r9, %r8
	xorq	%rdx, %r8
	andq	%rax, %r8
	andq	%rcx, %rdx
	xorq	%r8, %rdx
	movq	%rdx, 32(%r13)
	movq	%rdx, -72(%rsp)
	movq	%r9, %rdx
	movq	56(%rsp), %r13
	movq	280(%rsp), %r9
	andq	%rcx, %rdx
	xorq	%r8, %rdx
	movabsq	$2251799813685247, %r8
	movq	%rdx, -24(%rsp)
	movq	%rdx, 32(%r13)
	movq	%r9, %rdx
	andq	%r9, %r8
	xorq	%r12, %rdx
	movabsq	$2251799813685247, %r13
	movq	288(%rsp), %r9
	andq	%rax, %rdx
	andq	%r13, %r12
	movq	72(%rsp), %r13
	xorq	%rdx, %r8
	xorq	%rdx, %r12
	movq	%r8, 88(%rsp)
	movq	%r8, %rdx
	movq	-8(%rsp), %r8
	movq	%r12, 0(%r13)
	movq	%rdx, (%r8)
	movq	%r9, %rdx
	movabsq	$2251799813685247, %r8
	xorq	%r11, %rdx
	andq	%r8, %r11
	andq	%rax, %rdx
	movq	%r11, %r8
	movabsq	$2251799813685247, %r11
	xorq	%rdx, %r8
	andq	%r9, %r11
	movq	%rdx, %r9
	movq	296(%rsp), %rdx
	movq	%r8, 8(%r13)
	xorq	%r11, %r9
	movq	%r8, -120(%rsp)
	movq	-8(%rsp), %r8
	movq	%r9, -104(%rsp)
	movq	%rdx, %r13
	xorq	%rdi, %r13
	andq	104(%rsp), %r13
	movq	%r9, 8(%r8)
	movq	72(%rsp), %r9
	movq	%r13, %r11
	xorq	%r13, %rdi
	xorq	%rdx, %r11
	movq	%rdi, 16(%r9)
	movabsq	$2251799813685247, %rdx
	movq	%r11, 104(%rsp)
	movq	%r11, 16(%r8)
	movq	48(%rsp), %r8
	movq	%r8, %r13
	xorq	%r14, %r13
	andq	%rdx, %r14
	andq	%r8, %rdx
	andq	%rax, %r13
	movq	-8(%rsp), %r8
	xorq	%r13, %r14
	xorq	%rdx, %r13
	movq	128(%rsp), %rdx
	movq	%r14, 24(%r9)
	movq	%r13, 24(%r8)
	movq	%rdx, %r11
	xorq	%rbx, %r11
	movq	%r11, %r8
	andq	%rax, %r8
	movabsq	$2251799813685247, %rax
	andq	%rax, %rbx
	andq	%rdx, %rax
	xorq	%r8, %rbx
	xorq	%r8, %rax
	salb	240(%rsp)
	subl	$1, 308(%rsp)
	movq	%rbx, 32(%r9)
	movq	-8(%rsp), %r9
	movq	%rax, 32(%r9)
	jne	.L10
  lfence
	movq	%r14, 40(%rsp)
	movq	224(%rsp), %r14
	movq	%rax, %r8
	subq	$1, 336(%rsp)
	movq	%r15, 16(%rsp)
	movq	%rsi, %r15
	movq	336(%rsp), %rsi
	cmpq	%rsi, 344(%rsp)
	movq	-8(%rsp), %rax
	movq	%r14, -8(%rsp)
	movq	232(%rsp), %r14
	movq	216(%rsp), %rdx
	movq	-120(%rsp), %r11
	movq	-104(%rsp), %r9
	movq	%r14, 216(%rsp)
	jne	.L3
  lfence
	leaq	(%rbx,%rbx,8), %rax
	movq	%rdi, %r9
	movq	%rbp, 176(%rsp)
	movq	40(%rsp), %r15
	movq	%r12, %rdi
	movq	%rbx, %r8
	leaq	(%rbx,%rax,2), %rbp
	leaq	(%r9,%r9,8), %rax
	movq	%r10, 168(%rsp)
	movq	%rdi, -56(%rsp)
	movq	%r11, %r13
	leaq	(%r12,%r12), %r14
	leaq	(%r9,%rax,2), %rax
	leaq	(%rbp,%rbp), %r10
	leaq	(%r11,%r11), %r12
	leaq	(%rax,%rax), %rcx
	movq	%rax, 48(%rsp)
	movq	%rcx, %rax
	mulq	%r15
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	movq	%rax, %rsi
	movq	%rdx, %rdi
	leaq	(%r15,%r15,8), %rax
	addq	%rcx, %rsi
	movabsq	$2251799813685247, %rcx
	adcq	%rbx, %rdi
	movq	%rsi, %rbx
	movq	%rdi, %rsi
	leaq	(%r15,%rax,2), %rdi
	movq	%r13, %rax
	movq	%rbx, -120(%rsp)
	andq	-120(%rsp), %rcx
	mulq	%r14
	movq	%rsi, -112(%rsp)
	movq	%rdi, 40(%rsp)
	movq	-120(%rsp), %rsi
	movq	%rcx, %r11
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%r15
	movq	-112(%rsp), %rdi
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movabsq	$2251799813685247, %rcx
	adcq	%rbx, %rdi
	andq	%rsi, %rcx
	mulq	%r9
	movq	%rcx, -88(%rsp)
	movq	%rax, %rcx
	movq	%r13, %rax
	movq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	movabsq	$2251799813685247, %rsi
	movq	%rax, -120(%rsp)
	movq	%r15, %rax
	andq	-120(%rsp), %rsi
	mulq	%r14
	movq	%rdi, -112(%rsp)
	movq	-112(%rsp), %rdi
	movq	%rsi, %r10
	movq	-120(%rsp), %rsi
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	movq	%rsi, %rax
	movq	%rdi, %rdx
	movabsq	$2251799813685247, %rsi
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, -104(%rsp)
	movq	%r14, %rax
	movq	%rdx, -96(%rsp)
	andq	-104(%rsp), %rsi
	movabsq	$2251799813685247, %r14
	mulq	%r8
	movq	%rsi, -120(%rsp)
	movq	%rax, %rcx
	movq	%r12, %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	movq	-96(%rsp), %rdx
	shrdq	$51, %rdx, %rax
	shrq	$51, %rdx
	movq	%rax, %rsi
	movq	%rdx, %rdi
	addq	%rcx, %rsi
	movabsq	$2251799813685247, %rcx
	adcq	%rbx, %rdi
	andq	%rsi, %r14
	shrdq	$51, %rdi, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	movabsq	$2251799813685247, %rsi
	addq	%r11, %rax
	andq	%rax, %rcx
	shrq	$51, %rax
	addq	-88(%rsp), %rax
	movq	%rcx, %r11
	leaq	(%rcx,%rcx), %r12
	movq	%r11, 104(%rsp)
	andq	%rax, %rsi
	shrq	$51, %rax
	addq	%r10, %rax
	leaq	(%rsi,%rsi), %rdx
	movq	%rax, -104(%rsp)
	leaq	(%r14,%r14,8), %rax
	movq	%rdx, %r10
	leaq	(%r14,%rax,2), %rax
	leaq	(%rax,%rax), %rdi
	movq	%rax, 72(%rsp)
	movq	%rsi, %rax
	mulq	%rdi
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r11
	movq	-120(%rsp), %r11
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	-104(%rsp), %rdx
	leaq	(%rdx,%rdx,8), %rax
	leaq	(%rdx,%rax,2), %rdx
	leaq	(%rdx,%rdx), %rax
	movq	%rdx, 56(%rsp)
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%r11,%r11,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -88(%rsp)
	leaq	(%r11,%rax,2), %rdx
	movabsq	$2251799813685247, %r11
	movq	%rdx, 80(%rsp)
	movq	%rdx, %rax
	movq	%rbx, -80(%rsp)
	mulq	-120(%rsp)
	andq	-88(%rsp), %r11
	movq	%rax, %rcx
	movq	%r12, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	movq	-80(%rsp), %rdx
	shrdq	$51, %rdx, %rax
	shrq	$51, %rdx
	addq	%rax, %rcx
	movq	%rdi, %rax
	movq	-104(%rsp), %rdi
	adcq	%rdx, %rbx
	movq	%rcx, -88(%rsp)
	movq	%rbx, %rdx
	movabsq	$2251799813685247, %rbx
	andq	-88(%rsp), %rbx
	movq	%rdx, -80(%rsp)
	mulq	-120(%rsp)
	movq	%rbx, -24(%rsp)
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%rdi, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	movq	-80(%rsp), %rdx
	shrdq	$51, %rdx, %rax
	shrq	$51, %rdx
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -88(%rsp)
	movabsq	$2251799813685247, %rdx
	andq	-88(%rsp), %rdx
	movq	%rbx, -80(%rsp)
	movq	%rdx, -40(%rsp)
	mulq	%r14
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	%r12, %rax
	mulq	-120(%rsp)
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %rax
	movabsq	$2251799813685247, %rcx
	movq	%rbx, -80(%rsp)
	movq	-104(%rsp), %rbx
	movq	%rax, -88(%rsp)
	andq	-88(%rsp), %rcx
	movq	%rbx, %rax
	mulq	%rbx
	movq	%rcx, %rdi
	movq	%rax, -8(%rsp)
	movq	%rdx, (%rsp)
	movq	%r10, %rax
	mulq	-120(%rsp)
	movq	%rax, %rcx
	movq	%r12, %rax
	addq	-8(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	(%rsp), %rbx
	movabsq	$2251799813685247, %r12
	mulq	%r14
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	movq	-24(%rsp), %r10
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %rax
	movabsq	$2251799813685247, %rdx
	shrdq	$51, %rbx, %rax
	andq	%rcx, %rdx
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	movq	%rdx, -8(%rsp)
	leaq	(%rcx,%rax,2), %rax
	addq	%r11, %rax
	movabsq	$2251799813685247, %r11
	andq	%rax, %r11
	shrq	$51, %rax
	leaq	(%rax,%r10), %rdx
	movq	-40(%rsp), %r10
	movq	%r11, %rcx
	leaq	(%r11,%r11), %rbx
	andq	%rdx, %r12
	shrq	$51, %rdx
	movq	%r12, %rax
	leaq	(%rdx,%r10), %r12
	movq	-8(%rsp), %rdx
	movq	%rax, -24(%rsp)
	leaq	(%rax,%rax), %r10
	movq	%rbx, -40(%rsp)
	leaq	(%rdx,%rdx,8), %rax
	leaq	(%rdx,%rax,2), %r11
	movq	%rcx, %rax
	mulq	%rcx
	leaq	(%r11,%r11), %rbx
	movq	%rbx, -88(%rsp)
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	-88(%rsp), %rax
	mulq	-24(%rsp)
	addq	%rax, %rcx
	leaq	(%r12,%r12,8), %rax
	adcq	%rdx, %rbx
	leaq	(%r12,%rax,2), %rax
	addq	%rax, %rax
	mulq	%rdi
	addq	%rax, %rcx
	leaq	(%rdi,%rdi,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdx
	movq	%rbx, %rcx
	movq	%rdx, 24(%rsp)
	movabsq	$2251799813685247, %rbx
	movq	%rcx, 32(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	andq	24(%rsp), %rbx
	movq	%rcx, %rax
	mulq	%rdi
	movq	%rbx, 88(%rsp)
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	-24(%rsp), %rax
	mulq	-40(%rsp)
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	24(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	32(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, 24(%rsp)
	andq	24(%rsp), %rcx
	movq	%rbx, 32(%rsp)
	movq	%rcx, 112(%rsp)
	movq	-24(%rsp), %rcx
	movq	%rcx, %rax
	mulq	%rcx
	movq	%rax, -24(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, -16(%rsp)
	mulq	%rdi
	movq	%rax, %rcx
	movq	-40(%rsp), %rax
	addq	-24(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-16(%rsp), %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	24(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	32(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movabsq	$2251799813685247, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdx
	movq	%rdx, -88(%rsp)
	andq	-88(%rsp), %rax
	movq	%rbx, -80(%rsp)
	movq	%rax, 24(%rsp)
	movq	-40(%rsp), %rax
	mulq	%rdi
	movq	%rax, -24(%rsp)
	movq	%r11, %rax
	movq	-8(%rsp), %r11
	movq	%rdx, -16(%rsp)
	mulq	%r11
	movq	%rax, %rcx
	movq	%r10, %rax
	addq	-24(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-16(%rsp), %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, -24(%rsp)
	movq	%r10, %rax
	andq	-24(%rsp), %rcx
	mulq	%rdi
	movq	%rbx, -16(%rsp)
	movq	%rcx, -88(%rsp)
	movq	%rax, -8(%rsp)
	movq	%r12, %rax
	movq	%rdx, (%rsp)
	mulq	%r12
	movq	-16(%rsp), %r12
	movq	%rax, %rcx
	movq	-40(%rsp), %rax
	addq	-8(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	(%rsp), %rbx
	mulq	%r11
	movq	-24(%rsp), %r11
	addq	%rcx, %rax
	movabsq	$2251799813685247, %rcx
	adcq	%rbx, %rdx
	shrdq	$51, %r12, %r11
	shrq	$51, %r12
	addq	%rax, %r11
	adcq	%rdx, %r12
	andq	%r11, %rcx
	shrdq	$51, %r12, %r11
	movabsq	$2251799813685247, %r12
	movq	%rcx, %r10
	leaq	(%r11,%r11,8), %rax
	movq	%r10, -40(%rsp)
	leaq	(%r11,%rax,2), %rax
	addq	88(%rsp), %rax
	movabsq	$2251799813685247, %r11
	andq	%rax, %r11
	shrq	$51, %rax
	addq	112(%rsp), %rax
	movq	%r11, %rdi
	andq	%rax, %r12
	shrq	$51, %rax
	movq	%rax, %rdx
	leaq	0(%r13,%r13,8), %rax
	addq	24(%rsp), %rdx
	leaq	0(%r13,%rax,2), %rcx
	movq	%rcx, %rax
	movq	%rdx, %r11
	mulq	%r10
	movabsq	$2251799813685247, %r10
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	-88(%rsp), %rax
	mulq	48(%rsp)
	addq	%rax, %rcx
	movq	-56(%rsp), %rax
	movq	%r11, -24(%rsp)
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	40(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	48(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdx
	movq	%rdx, -8(%rsp)
	andq	-8(%rsp), %r10
	mulq	-40(%rsp)
	movq	%rbx, (%rsp)
	movq	%r10, 24(%rsp)
	movq	-88(%rsp), %r10
	movq	%rax, %rcx
	movq	40(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%r13, %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	-56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r11, %rax
	movabsq	$2251799813685247, %r11
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rcx, %rax
	movq	-8(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -8(%rsp)
	andq	-8(%rsp), %r11
	mulq	%rbp
	movq	%rbx, (%rsp)
	movq	%r11, 48(%rsp)
	movq	%rax, 88(%rsp)
	movq	%rdx, 96(%rsp)
	movq	40(%rsp), %rax
	mulq	-40(%rsp)
	movq	%rdx, %rcx
	movq	%rax, %rdx
	addq	88(%rsp), %rdx
	adcq	96(%rsp), %rcx
	movq	%r9, %rax
	movq	%rcx, %rbx
	movq	%rdx, %rcx
	mulq	%rdi
	movq	%rax, %r10
	movq	%rdx, %r11
	movq	%r13, %rax
	addq	%rcx, %r10
	adcq	%rbx, %r11
	mulq	%r12
	addq	%r10, %rax
	adcq	%r11, %rdx
	movq	%rax, %rcx
	movq	-24(%rsp), %rax
	movq	%rdx, %rbx
	movabsq	$2251799813685247, %r11
	mulq	-56(%rsp)
	addq	%rcx, %rax
	movq	-8(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, -8(%rsp)
	andq	-8(%rsp), %r11
	movq	%rbx, (%rsp)
	movq	%r11, 40(%rsp)
	movq	-88(%rsp), %rax
	mulq	-56(%rsp)
	movq	%rax, 88(%rsp)
	movq	%rdx, 96(%rsp)
	movq	%rbp, %rax
	mulq	-40(%rsp)
	movabsq	$2251799813685247, %rbp
	movq	%rax, %r10
	movq	%r15, %rax
	addq	88(%rsp), %r10
	movq	%rdx, %r11
	adcq	96(%rsp), %r11
	mulq	%rdi
	addq	%r10, %rax
	adcq	%r11, %rdx
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	%rax, %rcx
	movq	-24(%rsp), %rax
	adcq	%rbx, %rdx
	movq	%rdx, %rbx
	mulq	%r13
	addq	%rcx, %rax
	movq	-8(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	-40(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -8(%rsp)
	andq	-8(%rsp), %rbp
	mulq	-56(%rsp)
	movq	%rbx, (%rsp)
	movq	%rax, -56(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, -48(%rsp)
	mulq	%r13
	movq	72(%rsp), %r13
	movq	%rax, %r10
	movq	%r8, %rax
	addq	-56(%rsp), %r10
	movq	%rdx, %r11
	adcq	-48(%rsp), %r11
	mulq	%rdi
	movabsq	$2251799813685247, %rdi
	addq	%r10, %rax
	movq	-8(%rsp), %r10
	adcq	%r11, %rdx
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	movq	%rcx, %r11
	movq	80(%rsp), %r15
	mulq	%r12
	movq	%rbx, %r12
	addq	%rax, %r11
	movq	-24(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r9
	addq	%r11, %rax
	movq	(%rsp), %r11
	adcq	%r12, %rdx
	movabsq	$2251799813685247, %r12
	shrdq	$51, %r11, %r10
	shrq	$51, %r11
	movq	%r10, %r8
	movq	%r11, %r9
	movq	40(%rsp), %r10
	addq	%rax, %r8
	adcq	%rdx, %r9
	andq	%r8, %r12
	shrdq	$51, %r9, %r8
	movq	104(%rsp), %r9
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %rax
	addq	24(%rsp), %rax
	movabsq	$2251799813685247, %r8
	andq	%rax, %r8
	shrq	$51, %rax
	addq	48(%rsp), %rax
	movq	%r8, %r11
	andq	%rax, %rdi
	shrq	$51, %rax
	leaq	(%rax,%r10), %r8
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	56(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r13, %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movabsq	$2251799813685247, %rax
	movq	%rcx, -88(%rsp)
	adcq	%rdx, %rbx
	andq	-88(%rsp), %rax
	movq	%rbx, -80(%rsp)
	movq	%rax, %r10
	movq	56(%rsp), %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r13, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movabsq	$2251799813685247, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdx
	movq	%rdx, -88(%rsp)
	andq	-88(%rsp), %rax
	movq	%rbx, -80(%rsp)
	movq	%rax, -56(%rsp)
	movq	%r13, %rax
	mulq	%rbp
	movq	%rax, -40(%rsp)
	movq	%r15, %rax
	movq	%rdx, -32(%rsp)
	mulq	%r12
	movq	-104(%rsp), %r15
	movq	%rax, %rcx
	movq	%r15, %rax
	addq	-40(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-32(%rsp), %rbx
	mulq	%r11
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	movq	%rbx, %rdx
	movabsq	$2251799813685247, %rbx
	andq	-104(%rsp), %rbx
	movq	%rdx, -96(%rsp)
	mulq	%rbp
	movq	%rbx, -88(%rsp)
	movq	%rax, -40(%rsp)
	movq	%r13, %rax
	movq	%rdx, -32(%rsp)
	mulq	%r12
	movq	%rax, %rcx
	addq	-40(%rsp), %rcx
	movq	%rdx, %rbx
	movq	%r11, %rax
	adcq	-32(%rsp), %rbx
	mulq	-120(%rsp)
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rcx
	movq	%r8, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-104(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-96(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	movabsq	$2251799813685247, %rdx
	andq	-104(%rsp), %rdx
	movq	%rbx, -96(%rsp)
	movq	%rdx, 48(%rsp)
	mulq	%r12
	movq	%rax, -40(%rsp)
	movq	%rsi, %rax
	movq	%rdx, -32(%rsp)
	mulq	%rbp
	movq	%rax, %rcx
	movq	%r14, %rax
	addq	-40(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-32(%rsp), %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	-120(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r13
	movq	-104(%rsp), %rcx
	movq	%rbx, %r14
	movq	-96(%rsp), %rbx
	mulq	%rdi
	addq	%rax, %r13
	movq	%r15, %rax
	adcq	%rdx, %r14
	mulq	%r8
	addq	%r13, %rax
	adcq	%r14, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %r14
	movabsq	$2251799813685247, %rcx
	adcq	%rdx, %rbx
	andq	%r14, %rcx
	movq	%rcx, %r9
	movq	%r14, %rcx
	shrdq	$51, %rbx, %rcx
	movq	%r9, 216(%rsp)
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	movabsq	$2251799813685247, %rcx
	addq	%r10, %rax
	andq	%rax, %rcx
	shrq	$51, %rax
	addq	-56(%rsp), %rax
	movq	%rcx, %rbx
	movq	%rcx, 112(%rsp)
	movabsq	$2251799813685247, %rcx
	leaq	(%rbx,%rbx), %rsi
	andq	%rax, %rcx
	shrq	$51, %rax
	movq	%rax, %r10
	leaq	(%r9,%r9,8), %rax
	movq	%rcx, %r15
	leaq	(%rcx,%rcx), %r14
	addq	-88(%rsp), %r10
	movq	%r15, 120(%rsp)
	leaq	(%r9,%rax,2), %rax
	leaq	(%rax,%rax), %r13
	movq	%rax, 184(%rsp)
	movq	%rbx, %rax
	mulq	%rbx
	movq	%r10, 40(%rsp)
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r13
	movq	48(%rsp), %r15
	addq	%rax, %rcx
	leaq	(%r10,%r10,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	leaq	(%r10,%rax,2), %rax
	movq	%rbx, %r10
	addq	%rax, %rax
	mulq	%r15
	addq	%rax, %r9
	leaq	(%r15,%r15,8), %rax
	adcq	%rdx, %r10
	leaq	(%r15,%rax,2), %rdx
	movq	120(%rsp), %rax
	movabsq	$2251799813685247, %r15
	andq	%r9, %r15
	movq	%rdx, 208(%rsp)
	mulq	%rsi
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	48(%rsp), %rax
	mulq	208(%rsp)
	addq	%rax, %rcx
	movq	40(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	movq	%r9, %rcx
	movq	%r10, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, -120(%rsp)
	movabsq	$2251799813685247, %rdx
	movq	120(%rsp), %rcx
	andq	-120(%rsp), %rdx
	movq	%rbx, -112(%rsp)
	movq	-112(%rsp), %rbx
	movq	%rcx, %rax
	movq	%rdx, -104(%rsp)
	mulq	%rcx
	movq	-120(%rsp), %rcx
	movq	%rax, %r9
	movq	%r13, %rax
	movq	48(%rsp), %r13
	movq	%rdx, %r10
	mulq	%r13
	addq	%rax, %r9
	movq	40(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r13, %rax
	movabsq	$2251799813685247, %r13
	adcq	%rdx, %r10
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %r9
	adcq	%rbx, %r10
	movabsq	$2251799813685247, %rbx
	mulq	%rsi
	andq	%r9, %rbx
	movq	%rbx, -120(%rsp)
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	216(%rsp), %rax
	mulq	184(%rsp)
	addq	%rax, %rcx
	movq	40(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rax, %r9
	movq	%r14, %rax
	movq	40(%rsp), %r14
	adcq	%rdx, %r10
	andq	%r9, %r13
	mulq	48(%rsp)
	movq	%rax, %rcx
	movq	%r14, %rax
	movq	%rdx, %rbx
	mulq	%r14
	movabsq	$2251799813685247, %r14
	addq	%rax, %rcx
	movq	%rsi, %rax
	movabsq	$2251799813685247, %rsi
	adcq	%rdx, %rbx
	mulq	216(%rsp)
	addq	%rcx, %rax
	movq	%r9, %rcx
	adcq	%rbx, %rdx
	movq	%r10, %rbx
	shrdq	$51, %r10, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	andq	%rax, %rsi
	shrdq	$51, %rdx, %rax
	movq	-104(%rsp), %rdx
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	%rax, %r15
	andq	%r15, %r14
	shrq	$51, %r15
	leaq	(%r15,%rdx), %rax
	movabsq	$2251799813685247, %r15
	andq	%rax, %r15
	shrq	$51, %rax
	addq	-120(%rsp), %rax
	movq	%rax, %r10
	leaq	(%r12,%r12,8), %rax
	movq	%r10, -120(%rsp)
	leaq	(%r12,%rax,2), %r9
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %rax
	movq	%r9, -104(%rsp)
	movq	%rax, -56(%rsp)
	leaq	0(%rbp,%rbp,8), %rax
	leaq	0(%rbp,%rax,2), %rax
	movq	%rax, -88(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%rsi
	movq	%rax, %rcx
	movq	-56(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r9, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	-88(%rsp)
	addq	%rax, %rcx
	movq	-56(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	movabsq	$2251799813685247, %rcx
	andq	%r9, %rcx
	movq	%rbx, %r10
	mulq	%rsi
	movq	%rcx, -40(%rsp)
	movq	%rax, %rcx
	movq	-88(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%rdi, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	-120(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	-104(%rsp)
	addq	%rcx, %rax
	movq	%r9, %rcx
	adcq	%rbx, %rdx
	movq	%r10, %rbx
	shrdq	$51, %r10, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -56(%rsp)
	movq	-56(%rsp), %rcx
	movq	%rbx, %rdx
	movabsq	$2251799813685247, %rbx
	andq	-56(%rsp), %rbx
	movq	%rdx, -48(%rsp)
	mulq	%r13
	movq	%rbx, -24(%rsp)
	movq	-48(%rsp), %rbx
	movq	%rax, %r9
	movq	-88(%rsp), %rax
	movq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%r14
	addq	%rax, %r9
	movq	%rdi, %rax
	adcq	%rdx, %r10
	mulq	%r15
	addq	%rax, %r9
	movq	-120(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r11
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movabsq	$2251799813685247, %rax
	adcq	%rdx, %rbx
	andq	%rcx, %rax
	movq	%rax, -88(%rsp)
	movq	%r11, %rax
	mulq	%r13
	movq	%rax, %r9
	movq	-104(%rsp), %rax
	movq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%rbp, %rax
	adcq	%rdx, %r10
	mulq	%r14
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%r15
	addq	%rax, %r9
	movq	-120(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rdi
	addq	%r9, %rax
	movabsq	$2251799813685247, %r9
	adcq	%r10, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	andq	%rcx, %r9
	mulq	%rsi
	movq	%rax, %r10
	movq	%rdi, %rax
	movq	%rdx, %r11
	mulq	%r13
	movabsq	$2251799813685247, %r13
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r12, %rax
	addq	%r10, %rsi
	adcq	%r11, %rdi
	mulq	%r14
	addq	%rax, %rsi
	movq	%rbp, %rax
	movabsq	$2251799813685247, %rbp
	adcq	%rdx, %rdi
	mulq	%r15
	addq	%rax, %rsi
	movq	-120(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r8
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rdx
	andq	%rsi, %r13
	shrdq	$51, %rdi, %rdx
	movabsq	$2251799813685247, %rdi
	leaq	(%rdx,%rdx,8), %rax
	leaq	(%rdx,%rax,2), %rax
	addq	-40(%rsp), %rax
	andq	%rax, %rbp
	shrq	$51, %rax
	addq	-24(%rsp), %rax
	movq	-88(%rsp), %rcx
	leaq	(%rbp,%rbp), %rsi
	andq	%rax, %rdi
	shrq	$51, %rax
	leaq	(%rax,%rcx), %r8
	leaq	(%rdi,%rdi), %rax
	movq	%rax, %r15
	leaq	0(%r13,%r13,8), %rax
	movq	%r15, -24(%rsp)
	leaq	0(%r13,%rax,2), %r12
	movq	%rdi, %rax
	leaq	(%r12,%r12), %r14
	mulq	%r14
	movq	%rax, %rcx
	movq	%rbp, %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	leaq	(%r8,%r8,8), %rax
	adcq	%rdx, %rbx
	leaq	(%r8,%rax,2), %rax
	movq	%rax, -40(%rsp)
	addq	%rax, %rax
	mulq	%r9
	addq	%rax, %rcx
	leaq	(%r9,%r9,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r10
	movabsq	$2251799813685247, %rcx
	movq	%rbx, %r11
	leaq	(%r9,%rax,2), %rbx
	andq	%r10, %rcx
	movq	%rcx, -88(%rsp)
	movq	%rbx, %rax
	movq	%rbx, -56(%rsp)
	mulq	%r9
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r14, %rax
	movabsq	$2251799813685247, %r14
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rdx
	shrdq	$51, %r11, %r10
	shrq	$51, %r11
	addq	%rcx, %r10
	adcq	%rbx, %r11
	andq	%r10, %rdx
	movq	%rdx, -104(%rsp)
	mulq	%r9
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r11, %r10
	shrq	$51, %r11
	addq	%rcx, %r10
	adcq	%rbx, %r11
	andq	%r10, %r14
	mulq	%r13
	movq	%r14, -120(%rsp)
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rcx, %rax
	movq	%r10, %rcx
	movabsq	$2251799813685247, %r10
	adcq	%rbx, %rdx
	movq	%r11, %rbx
	shrdq	$51, %r11, %rcx
	shrq	$51, %rbx
	movabsq	$2251799813685247, %r11
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	andq	%rcx, %r10
	mulq	%r8
	movq	%rax, %r14
	movq	-24(%rsp), %rax
	movq	%rdx, %r15
	mulq	%r9
	addq	%rax, %r14
	movq	%rsi, %rax
	movq	-120(%rsp), %rsi
	adcq	%rdx, %r15
	mulq	%r13
	addq	%r14, %rax
	movabsq	$2251799813685247, %r14
	adcq	%r15, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	andq	%rax, %r14
	shrdq	$51, %rdx, %rax
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-88(%rsp), %rax
	movabsq	$2251799813685247, %rcx
	andq	%rax, %rcx
	shrq	$51, %rax
	addq	-104(%rsp), %rax
	movq	%rcx, -120(%rsp)
	leaq	(%rcx,%rcx), %r15
	andq	%rax, %r11
	shrq	$51, %rax
	addq	%rax, %rsi
	leaq	(%r14,%r14,8), %rax
	leaq	(%r11,%r11), %rdx
	leaq	(%r14,%rax,2), %rbx
	movq	%rdx, -88(%rsp)
	movq	%rbx, 24(%rsp)
	addq	%rbx, %rbx
	movq	%rbx, %rax
	movq	%rbx, -104(%rsp)
	mulq	%r11
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rax
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r10
	addq	%rax, %rcx
	leaq	(%r10,%r10,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -120(%rsp)
	movabsq	$2251799813685247, %rdx
	andq	-120(%rsp), %rdx
	leaq	(%r10,%rax,2), %rcx
	movq	%rbx, -112(%rsp)
	movq	%rcx, %rax
	movq	%rdx, -8(%rsp)
	mulq	%r10
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, -120(%rsp)
	movq	-104(%rsp), %rax
	andq	-120(%rsp), %rcx
	movq	%rbx, -112(%rsp)
	mulq	%r10
	movq	%rcx, -24(%rsp)
	movq	%rax, -104(%rsp)
	movq	%r11, %rax
	movq	%rdx, -96(%rsp)
	mulq	%r11
	movabsq	$2251799813685247, %r11
	movq	%rax, %rcx
	movq	%rsi, %rax
	addq	-104(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-96(%rsp), %rbx
	mulq	%r15
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	movq	%rax, -120(%rsp)
	movq	24(%rsp), %rax
	adcq	%rbx, %rdx
	movq	%rdx, -112(%rsp)
	andq	-120(%rsp), %r11
	mulq	%r14
	movq	%r11, -104(%rsp)
	movabsq	$2251799813685247, %r11
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -120(%rsp)
	andq	-120(%rsp), %r11
	mulq	%rsi
	movq	%rbx, -112(%rsp)
	movq	-104(%rsp), %rsi
	movq	%rax, 24(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, 32(%rsp)
	mulq	%r10
	movq	%rax, %rcx
	movq	%r14, %rax
	addq	24(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	32(%rsp), %rbx
	movabsq	$2251799813685247, %r14
	mulq	%r15
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	andq	%rax, %r14
	shrdq	$51, %rdx, %rax
	movabsq	$2251799813685247, %rdx
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-8(%rsp), %rax
	movabsq	$2251799813685247, %rcx
	andq	%rax, %rcx
	shrq	$51, %rax
	addq	-24(%rsp), %rax
	leaq	(%rcx,%rcx), %r15
	movq	%rcx, -120(%rsp)
	andq	%rax, %rdx
	shrq	$51, %rax
	addq	%rax, %rsi
	leaq	(%r14,%r14,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rdx), %rdx
	leaq	(%r14,%rax,2), %rbx
	movq	%rdx, -88(%rsp)
	movq	%rbx, 24(%rsp)
	addq	%rbx, %rbx
	movq	%rbx, %rax
	movq	%rbx, -104(%rsp)
	mulq	%r10
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rax
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%r11,%r11,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -120(%rsp)
	movabsq	$2251799813685247, %rdx
	movq	%rbx, -112(%rsp)
	andq	-120(%rsp), %rdx
	leaq	(%r11,%rax,2), %rcx
	movq	%rcx, %rax
	movq	%rdx, -8(%rsp)
	mulq	%r11
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, -120(%rsp)
	movq	-104(%rsp), %rax
	andq	-120(%rsp), %rcx
	movq	%rbx, -112(%rsp)
	mulq	%r11
	movq	%rcx, -24(%rsp)
	movq	%rax, -104(%rsp)
	movq	%r10, %rax
	movq	%rdx, -96(%rsp)
	mulq	%r10
	movabsq	$2251799813685247, %r10
	movq	%rax, %rcx
	movq	%rsi, %rax
	addq	-104(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-96(%rsp), %rbx
	mulq	%r15
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	movq	%rax, -120(%rsp)
	movq	24(%rsp), %rax
	adcq	%rbx, %rdx
	movq	%rdx, -112(%rsp)
	andq	-120(%rsp), %r10
	mulq	%r14
	movq	%r10, -104(%rsp)
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, -120(%rsp)
	movq	%rsi, %rax
	andq	-120(%rsp), %rcx
	mulq	%rsi
	movq	%rbx, -112(%rsp)
	movq	%rcx, %r10
	movq	%rax, 24(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, 32(%rsp)
	mulq	%r11
	movabsq	$2251799813685247, %r11
	movq	%rax, %rcx
	movq	%r14, %rax
	addq	24(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	32(%rsp), %rbx
	movabsq	$2251799813685247, %r14
	mulq	%r15
	movq	-104(%rsp), %rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	andq	%rax, %r14
	shrdq	$51, %rdx, %rax
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-8(%rsp), %rax
	movabsq	$2251799813685247, %rcx
	andq	%rax, %rcx
	shrq	$51, %rax
	addq	-24(%rsp), %rax
	movq	%rcx, -120(%rsp)
	leaq	(%rcx,%rcx), %r15
	andq	%rax, %r11
	shrq	$51, %rax
	addq	%rax, %rsi
	leaq	(%r14,%r14,8), %rax
	leaq	(%r11,%r11), %rdx
	leaq	(%r14,%rax,2), %rbx
	movq	%rdx, -88(%rsp)
	movq	%rbx, 24(%rsp)
	addq	%rbx, %rbx
	movq	%rbx, %rax
	movq	%rbx, -104(%rsp)
	mulq	%r11
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rax
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r10
	addq	%rax, %rcx
	leaq	(%r10,%r10,8), %rax
	movq	%rcx, -120(%rsp)
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rdx
	andq	-120(%rsp), %rdx
	leaq	(%r10,%rax,2), %rcx
	movq	%rbx, -112(%rsp)
	movq	%rcx, %rax
	movq	%rdx, -8(%rsp)
	mulq	%r10
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movabsq	$2251799813685247, %rcx
	movq	%rax, -120(%rsp)
	movq	-104(%rsp), %rax
	andq	-120(%rsp), %rcx
	movq	%rbx, -112(%rsp)
	mulq	%r10
	movq	%rcx, -24(%rsp)
	movq	%rax, -104(%rsp)
	movq	%r11, %rax
	movq	%rdx, -96(%rsp)
	mulq	%r11
	movabsq	$2251799813685247, %r11
	movq	%rax, %rcx
	movq	%rsi, %rax
	addq	-104(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	-96(%rsp), %rbx
	mulq	%r15
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, -120(%rsp)
	movq	%rdx, -112(%rsp)
	movq	24(%rsp), %rax
	andq	-120(%rsp), %r11
	mulq	%r14
	movq	%r11, -104(%rsp)
	movabsq	$2251799813685247, %r11
	movq	%rax, %rcx
	movq	%r15, %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -120(%rsp)
	andq	-120(%rsp), %r11
	mulq	%rsi
	movq	%rbx, -112(%rsp)
	movq	-24(%rsp), %rsi
	movq	%rax, 24(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, 32(%rsp)
	mulq	%r10
	movq	%rax, %rcx
	movq	%r14, %rax
	addq	24(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	32(%rsp), %rbx
	movabsq	$2251799813685247, %r14
	mulq	%r15
	movabsq	$2251799813685247, %r15
	addq	%rcx, %rax
	movq	-120(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-112(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	andq	%rax, %r14
	shrdq	$51, %rdx, %rax
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-8(%rsp), %rax
	movabsq	$2251799813685247, %rcx
	andq	%rax, %rcx
	shrq	$51, %rax
	leaq	(%rax,%rsi), %rdx
	movq	-104(%rsp), %rsi
	leaq	(%r14,%r14,8), %rax
	andq	%rdx, %r15
	shrq	$51, %rdx
	leaq	(%r14,%rax,2), %rbx
	leaq	(%rdx,%rsi), %r10
	leaq	(%r15,%r15), %rdx
	movq	%rcx, %rax
	leaq	(%rcx,%rcx), %rsi
	movq	%rbx, 72(%rsp)
	movq	%rdx, -104(%rsp)
	mulq	%rcx
	movq	%rsi, -120(%rsp)
	leaq	(%rbx,%rbx), %rsi
	movq	%rsi, -88(%rsp)
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r15
	movabsq	$2251799813685247, %rsi
	addq	%rax, %rcx
	leaq	(%r10,%r10,8), %rax
	adcq	%rdx, %rbx
	leaq	(%r10,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%r11,%r11,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -24(%rsp)
	movq	%rcx, %rdx
	leaq	(%r11,%rax,2), %rcx
	andq	%rsi, %rdx
	movq	%rbx, -16(%rsp)
	movq	%rdx, -8(%rsp)
	movq	%rcx, %rax
	mulq	%r11
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r10
	addq	%rcx, %rax
	movq	-24(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-16(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -24(%rsp)
	andq	%rsi, %rcx
	mulq	%r15
	movq	%rbx, -16(%rsp)
	movq	-120(%rsp), %r15
	movq	%rcx, 24(%rsp)
	movq	%rax, 56(%rsp)
	movq	-88(%rsp), %rax
	movq	%rdx, 64(%rsp)
	mulq	%r11
	movq	%rax, %rcx
	movq	%r15, %rax
	addq	56(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	64(%rsp), %rbx
	mulq	%r10
	addq	%rcx, %rax
	movq	-24(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-16(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -88(%rsp)
	andq	%rsi, %rax
	movq	%rbx, -80(%rsp)
	movq	%rax, -24(%rsp)
	movq	%r15, %rax
	mulq	%r11
	movq	%rax, 56(%rsp)
	movq	72(%rsp), %rax
	movq	%rdx, 64(%rsp)
	mulq	%r14
	movq	%rax, %rcx
	movq	-104(%rsp), %rax
	addq	56(%rsp), %rcx
	movq	%rdx, %rbx
	adcq	64(%rsp), %rbx
	mulq	%r10
	addq	%rcx, %rax
	movq	-88(%rsp), %rcx
	adcq	%rbx, %rdx
	movq	-80(%rsp), %rbx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r15
	andq	%rsi, %r15
	mulq	%r11
	movq	%rax, -104(%rsp)
	movq	%r10, %rax
	movq	%rdx, -96(%rsp)
	mulq	%r10
	movq	%rax, %r10
	movq	-120(%rsp), %rax
	addq	-104(%rsp), %r10
	movq	%rdx, %r11
	adcq	-96(%rsp), %r11
	mulq	%r14
	addq	%r10, %rax
	adcq	%r11, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %r14
	shrdq	$51, %rbx, %rcx
	andq	%rsi, %r14
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-8(%rsp), %rax
	movq	%rax, %r10
	shrq	$51, %rax
	addq	24(%rsp), %rax
	andq	%rsi, %r10
	movq	%rax, %r11
	shrq	$51, %rax
	addq	-24(%rsp), %rax
	andq	%rsi, %r11
	movq	%rax, -120(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	movq	%r10, -104(%rsp)
	movq	%r11, -88(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%r14
	movq	%rax, %rcx
	movq	-40(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	-120(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	-56(%rsp)
	addq	%rax, %rcx
	movq	-40(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r10
	andq	%rsi, %rcx
	movq	%rcx, -24(%rsp)
	movq	%rbx, %r11
	mulq	%r14
	movq	%rax, %rcx
	movq	-56(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	-120(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	%r10, %rcx
	adcq	%rbx, %rdx
	movq	%r11, %rbx
	shrdq	$51, %r11, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdx
	andq	%rsi, %rdx
	movq	%rdx, -40(%rsp)
	mulq	%r12
	movq	%rax, %r10
	movq	-56(%rsp), %rax
	movq	%rdx, %r11
	mulq	%r14
	addq	%rax, %r10
	movq	-104(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%r8
	addq	%rax, %r10
	movq	-88(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%rdi
	addq	%rax, %r10
	movq	-120(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%rbp
	addq	%r10, %rax
	adcq	%r11, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -56(%rsp)
	mulq	%rbp
	movq	%rbx, -48(%rsp)
	movq	%rcx, %rbx
	andq	%rsi, %rbx
	movq	-56(%rsp), %rcx
	movq	%rbx, -8(%rsp)
	movq	-48(%rsp), %rbx
	movq	%rax, %r10
	movq	%r12, %rax
	movq	%rdx, %r11
	mulq	%r14
	addq	%rax, %r10
	movq	-104(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%r9
	addq	%rax, %r10
	movq	-88(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%r8
	addq	%rax, %r10
	movq	-120(%rsp), %rax
	adcq	%rdx, %r11
	mulq	%rdi
	addq	%r10, %rax
	adcq	%r11, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -56(%rsp)
	andq	%rsi, %rcx
	mulq	%rbp
	movq	%rbx, -48(%rsp)
	movq	%rcx, %r10
	movq	-48(%rsp), %rbx
	movq	%rcx, 104(%rsp)
	movq	-56(%rsp), %rcx
	movq	%rax, %r11
	movq	%r15, %rax
	movq	%rdx, %r12
	mulq	%rdi
	movq	%rax, %rdi
	movq	-104(%rsp), %rax
	movq	%rdx, %rbp
	addq	%r11, %rdi
	adcq	%r12, %rbp
	movq	%r10, %r12
	mulq	%r13
	movq	%rsi, %r13
	addq	%rax, %rdi
	movq	-88(%rsp), %rax
	adcq	%rdx, %rbp
	mulq	%r9
	addq	%rax, %rdi
	movq	-120(%rsp), %rax
	adcq	%rdx, %rbp
	mulq	%r8
	addq	%rdi, %rax
	adcq	%rbp, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %rdi
	movq	%rcx, %rdx
	shrdq	$51, %rbx, %rdi
	andq	%rsi, %rdx
	leaq	(%rdi,%rdi,8), %rax
	movq	%rdx, 200(%rsp)
	movq	%rdx, %rbp
	leaq	(%rdi,%rax,2), %rax
	addq	-24(%rsp), %rax
	movq	%rax, %r9
	shrq	$51, %rax
	addq	-40(%rsp), %rax
	andq	%rsi, %r9
	movq	$10, -40(%rsp)
	movq	%r9, 24(%rsp)
	movq	%rax, %r14
	shrq	$51, %rax
	addq	-8(%rsp), %rax
	andq	%rsi, %r14
	movq	%r14, 72(%rsp)
	movq	%rax, %r15
	movq	%rax, 56(%rsp)
	.p2align 4,,10
	.p2align 3
.L4:
  lfence
	leaq	0(%rbp,%rbp,8), %rax
	leaq	(%r9,%r9), %r8
	leaq	(%r14,%r14), %rdi
	leaq	0(%rbp,%rax,2), %rax
	movq	%rdi, -120(%rsp)
	leaq	(%rax,%rax), %r11
	movq	%rax, -56(%rsp)
	leaq	(%r15,%r15,8), %rax
	leaq	(%r15,%rax,2), %rcx
	addq	%rcx, %rcx
	movq	%rcx, %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	mulq	%rbp
	movq	%rbx, %r10
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	leaq	(%r12,%r12,8), %rax
	movq	%rcx, -104(%rsp)
	adcq	%rdx, %rbx
	leaq	(%r12,%rax,2), %rcx
	movq	%rbx, -96(%rsp)
	movq	%r9, %rbx
	andq	%r13, %rbx
	movq	%rcx, %rax
	movq	%rbx, -88(%rsp)
	mulq	%r12
	movq	%rax, %rcx
	movq	%r14, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, %r10
	mulq	%r15
	andq	%r13, %r10
	movq	%rax, %rsi
	movq	%r14, %rax
	movq	%rdx, %rdi
	mulq	%r14
	addq	%rax, %rsi
	movq	%r11, %rax
	adcq	%rdx, %rdi
	mulq	%r12
	addq	%rax, %rsi
	movq	%r12, %rax
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r11
	mulq	%r8
	andq	%r13, %r11
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	-56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	movq	-96(%rsp), %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %r12
	shrdq	$51, %rbx, %rcx
	andq	%r13, %r12
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rbp
	shrdq	$51, %rdx, %rax
	andq	%r13, %rbp
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %r15
	addq	-88(%rsp), %r15
	movq	%r15, %r9
	shrq	$51, %r15
	addq	%r10, %r15
	andq	%r13, %r9
	movq	%r15, %r14
	shrq	$51, %r15
	andq	%r13, %r14
	addq	%r11, %r15
	subq	$1, -40(%rsp)
	jne	.L4
  lfence
	movq	200(%rsp), %rbx
	movq	72(%rsp), %r8
	movq	104(%rsp), %rdi
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r11
	leaq	(%r8,%r8,8), %rax
	movq	56(%rsp), %rbx
	leaq	(%r8,%rax,2), %rax
	movq	%r11, 88(%rsp)
	movq	%rax, 240(%rsp)
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r10
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rsi
	movq	24(%rsp), %rax
	movq	%r10, 232(%rsp)
	movq	%rsi, 192(%rsp)
	mulq	%r9
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	240(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	movq	%rax, %rsi
	movq	%rdx, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, %r10
	movq	24(%rsp), %rax
	mulq	%r14
	movq	%rax, %rcx
	movq	%r8, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	232(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	192(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, %r11
	movq	24(%rsp), %rax
	mulq	%r15
	movq	%rax, %rcx
	movq	56(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	192(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, %r8
	movq	24(%rsp), %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	104(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, 128(%rsp)
	movq	%rbp, %rax
	mulq	24(%rsp)
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	%r9, %rax
	mulq	200(%rsp)
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	72(%rsp)
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	104(%rsp)
	addq	%rax, %rcx
	movq	%r15, %rax
	movabsq	$2251799813685247, %r15
	adcq	%rdx, %rbx
	mulq	56(%rsp)
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %rdi
	shrdq	$51, %rbx, %rcx
	andq	%r13, %rdi
	leaq	(%rcx,%rcx,8), %rax
	movq	%rdi, 224(%rsp)
	leaq	(%rcx,%rax,2), %rax
	addq	%rax, %r10
	movq	%r10, %r9
	shrq	$51, %r10
	addq	%r10, %r11
	andq	%r13, %r9
	andq	%r11, %r13
	shrq	$51, %r11
	movq	%r9, 136(%rsp)
	leaq	(%r11,%r8), %rcx
	movq	%r13, 80(%rsp)
	movq	%r13, %rsi
	movq	%rdi, %r11
	movq	%rcx, 152(%rsp)
	movq	%rcx, %r14
	movq	128(%rsp), %rbp
	movq	$20, -8(%rsp)
	.p2align 4,,10
	.p2align 3
.L5:
  lfence
	leaq	(%r11,%r11,8), %rax
	leaq	(%r9,%r9), %rdi
	leaq	(%rsi,%rsi), %r12
	leaq	(%r11,%rax,2), %rax
	movq	%r12, -104(%rsp)
	movq	%rdi, -120(%rsp)
	leaq	(%rax,%rax), %r8
	movq	%rax, -24(%rsp)
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %rcx
	addq	%rcx, %rcx
	movq	%rcx, %rax
	mulq	%rbp
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%rdi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	mulq	%r11
	movq	%rbx, %r10
	movq	%rax, %rcx
	movq	%r12, %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	leaq	0(%rbp,%rbp,8), %rax
	movq	%rcx, %r12
	movq	%r9, %rcx
	adcq	%rdx, %rbx
	andq	%r15, %rcx
	movq	%rbx, %r13
	movq	%rcx, -88(%rsp)
	leaq	0(%rbp,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%rbp
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%rdi, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, -56(%rsp)
	mulq	%r14
	movq	%rbx, -48(%rsp)
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	-56(%rsp), %rcx
	movq	%rbx, -40(%rsp)
	movq	-48(%rsp), %rbx
	movq	%rax, %r9
	movq	%rsi, %rax
	movq	%rdx, %r10
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r8, %rax
	addq	%r9, %rsi
	adcq	%r10, %rdi
	mulq	%rbp
	addq	%rax, %rsi
	movq	-120(%rsp), %rax
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r8
	mulq	%rbp
	andq	%r15, %r8
	movq	%rax, %rcx
	movq	-104(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	-24(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %rax
	shrdq	$51, %rdi, %rsi
	movq	%rbx, %rdx
	shrq	$51, %rdi
	addq	%rsi, %rax
	adcq	%rdi, %rdx
	movq	%rax, %rbp
	shrdq	$51, %rdx, %rax
	andq	%r15, %rbp
	shrq	$51, %rdx
	addq	%r12, %rax
	adcq	%r13, %rdx
	movq	%rax, %r11
	shrdq	$51, %rdx, %rax
	andq	%r15, %r11
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %r14
	addq	-88(%rsp), %r14
	movq	%r14, %r9
	shrq	$51, %r14
	addq	-40(%rsp), %r14
	andq	%r15, %r9
	movq	%r14, %rsi
	shrq	$51, %r14
	andq	%r15, %rsi
	addq	%r8, %r14
	subq	$1, -8(%rsp)
	jne	.L5
  lfence
	movq	224(%rsp), %rbx
	movq	128(%rsp), %rdi
	movq	%r11, %r8
	movq	%rsi, %r13
	movq	$10, -40(%rsp)
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r12
	movq	152(%rsp), %rbx
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r11
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %r10
	movq	136(%rsp), %rax
	movq	80(%rsp), %rdi
	mulq	%r9
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	leaq	(%rdi,%rdi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rdi,%rax,2), %rax
	mulq	%r8
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	movq	%rax, %rsi
	movq	%rdx, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, -120(%rsp)
	movq	136(%rsp), %rax
	mulq	%r13
	movq	%rax, %rcx
	movq	80(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r11
	mulq	%r14
	andq	%r15, %r11
	movq	%rax, %rcx
	movq	152(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	80(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r10
	mulq	%rbp
	andq	%r15, %r10
	movq	%rax, %rcx
	movq	128(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	152(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	80(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r12
	mulq	%r8
	andq	%r15, %r12
	movq	%rax, %rcx
	movq	224(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	80(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	128(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	movabsq	$2251799813685247, %r13
	addq	%rax, %rcx
	movq	152(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	movq	%r15, %r14
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rcx
	movq	%rsi, %rbp
	shrdq	$51, %rdi, %rcx
	andq	%r15, %rbp
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-120(%rsp), %rax
	movq	%rax, %r9
	shrq	$51, %rax
	addq	%rax, %r11
	andq	%r15, %r9
	andq	%r11, %r14
	shrq	$51, %r11
	leaq	(%r11,%r10), %r15
	.p2align 4,,10
	.p2align 3
.L6:
  lfence
	leaq	0(%rbp,%rbp,8), %rax
	leaq	(%r9,%r9), %r8
	leaq	(%r14,%r14), %rdi
	leaq	0(%rbp,%rax,2), %rax
	movq	%rdi, -120(%rsp)
	leaq	(%rax,%rax), %r11
	movq	%rax, -56(%rsp)
	leaq	(%r15,%r15,8), %rax
	leaq	(%r15,%rax,2), %rcx
	addq	%rcx, %rcx
	movq	%rcx, %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	%r9, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	mulq	%rbp
	movq	%rbx, %r10
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r15, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	leaq	(%r12,%r12,8), %rax
	movq	%rcx, -104(%rsp)
	adcq	%rdx, %rbx
	leaq	(%r12,%rax,2), %rcx
	movq	%rbx, -96(%rsp)
	movq	%r9, %rbx
	andq	%r13, %rbx
	movq	%rcx, %rax
	movq	%rbx, -88(%rsp)
	mulq	%r12
	movq	%rax, %rcx
	movq	%r14, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, %r10
	mulq	%r15
	andq	%r13, %r10
	movq	%rax, %rsi
	movq	%r14, %rax
	movq	%rdx, %rdi
	mulq	%r14
	addq	%rax, %rsi
	movq	%r11, %rax
	adcq	%rdx, %rdi
	mulq	%r12
	addq	%rax, %rsi
	movq	%r12, %rax
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r11
	mulq	%r8
	andq	%r13, %r11
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	-56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	-104(%rsp), %rax
	adcq	%rdx, %rbx
	movq	-96(%rsp), %rdx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %r12
	shrdq	$51, %rbx, %rcx
	andq	%r13, %r12
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rbp
	shrdq	$51, %rdx, %rax
	andq	%r13, %rbp
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %r15
	addq	-88(%rsp), %r15
	movq	%r15, %r9
	shrq	$51, %r15
	addq	%r10, %r15
	andq	%r13, %r9
	movq	%r15, %r14
	shrq	$51, %r15
	andq	%r13, %r14
	addq	%r11, %r15
	subq	$1, -40(%rsp)
	jne	.L6
  lfence
	movq	24(%rsp), %r11
	movq	88(%rsp), %r10
	movq	$50, -40(%rsp)
	movq	%r11, %rax
	mulq	%r9
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	240(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	192(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	232(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r11, %rax
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r8
	mulq	%r14
	andq	%r13, %r8
	movq	%rax, %rcx
	movq	72(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	232(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	192(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, %r10
	movq	%r11, %rax
	mulq	%r15
	movq	%rax, %rcx
	movq	56(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	192(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, %r11
	movq	24(%rsp), %rax
	mulq	%r12
	movq	%rax, %rcx
	movq	104(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r15
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r13, %rax
	movq	%rax, 80(%rsp)
	movq	24(%rsp), %rax
	mulq	%rbp
	movq	80(%rsp), %rbp
	movq	%rax, %rcx
	movq	200(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r15
	movabsq	$2251799813685247, %r15
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %r12
	shrdq	$51, %rbx, %rcx
	andq	%r13, %r12
	leaq	(%rcx,%rcx,8), %rax
	movq	%r12, 152(%rsp)
	leaq	(%rcx,%rax,2), %rax
	addq	%rax, %r8
	movq	%r8, %r9
	shrq	$51, %r8
	addq	%r8, %r10
	andq	%r13, %r9
	andq	%r10, %r13
	shrq	$51, %r10
	movq	%r9, 24(%rsp)
	leaq	(%r10,%r11), %rcx
	movq	%r13, -24(%rsp)
	movq	%r9, %rdi
	movq	%r13, %rsi
	movq	%rcx, -8(%rsp)
	movq	%rcx, %r14
	.p2align 4,,10
	.p2align 3
.L7:
  lfence
	leaq	(%rsi,%rsi), %rax
	leaq	(%rdi,%rdi), %r11
	movq	%rax, -120(%rsp)
	leaq	(%r12,%r12,8), %rax
	leaq	(%r12,%rax,2), %r13
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %rcx
	leaq	(%r13,%r13), %r8
	leaq	(%rcx,%rcx), %rbx
	movq	%rbx, %rax
	mulq	%rbp
	movq	%rax, %r9
	movq	%rdi, %rax
	movq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r11, %rax
	adcq	%rdx, %r10
	mulq	%r12
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	leaq	0(%rbp,%rbp,8), %rax
	movq	%rcx, -104(%rsp)
	adcq	%rdx, %rbx
	leaq	0(%rbp,%rax,2), %rcx
	movq	%rbx, -96(%rsp)
	movq	%r9, %rbx
	andq	%r15, %rbx
	movq	%rcx, %rax
	movq	%rbx, -88(%rsp)
	mulq	%rbp
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, %rdi
	mulq	%r14
	andq	%r15, %rdi
	movq	%rdi, -56(%rsp)
	movq	%rax, %r9
	movq	%rsi, %rax
	movq	%rdx, %r10
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r8, %rax
	addq	%r9, %rsi
	adcq	%r10, %rdi
	mulq	%rbp
	addq	%rax, %rsi
	movq	%rbp, %rax
	adcq	%rdx, %rdi
	movq	%rsi, %r9
	shrdq	$51, %rbx, %rcx
	movq	%rdi, %r10
	shrq	$51, %rbx
	addq	%rcx, %r9
	adcq	%rbx, %r10
	movq	%r9, %r8
	mulq	%r11
	andq	%r15, %r8
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	movq	%r9, %rsi
	movq	%r10, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rbp
	movq	%rsi, %rcx
	movq	-104(%rsp), %rsi
	movq	%rdi, %rbx
	andq	%r15, %rbp
	shrdq	$51, %rdi, %rcx
	movq	-96(%rsp), %rdi
	shrq	$51, %rbx
	addq	%rcx, %rsi
	movq	%rsi, %rcx
	movq	%rsi, %r12
	adcq	%rbx, %rdi
	andq	%r15, %r12
	shrdq	$51, %rdi, %rcx
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %r14
	addq	-88(%rsp), %r14
	movq	%r14, %rbx
	shrq	$51, %r14
	addq	-56(%rsp), %r14
	andq	%r15, %rbx
	movq	%rbx, %rdi
	movq	%r14, %rsi
	shrq	$51, %r14
	andq	%r15, %rsi
	addq	%r8, %r14
	subq	$1, -40(%rsp)
	jne	.L7
  lfence
	movq	%rbx, %r9
	movq	152(%rsp), %rbx
	movq	-24(%rsp), %r11
	movq	80(%rsp), %rdi
	movq	%rsi, %r13
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r10
	leaq	(%r11,%r11,8), %rax
	movq	-8(%rsp), %rbx
	leaq	(%r11,%rax,2), %rax
	movq	%r10, 56(%rsp)
	movq	%rax, 224(%rsp)
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r8
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rsi
	movq	24(%rsp), %rax
	movq	%r8, 200(%rsp)
	movq	%rsi, 136(%rsp)
	mulq	%r9
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	224(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	movq	%rax, %rsi
	movq	%rdx, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, %r8
	movq	24(%rsp), %rax
	mulq	%r13
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	200(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, %r10
	movq	24(%rsp), %rax
	mulq	%r14
	movq	%rax, %rcx
	movq	-8(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, %r11
	movq	24(%rsp), %rax
	mulq	%rbp
	movq	%rax, %rcx
	movq	80(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	-8(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	-24(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, 104(%rsp)
	movq	%r12, %rax
	mulq	24(%rsp)
	movq	%rax, %rcx
	movq	%rdx, %rbx
	movq	%r9, %rax
	mulq	152(%rsp)
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	-24(%rsp)
	addq	%rax, %rcx
	movq	%r13, %rax
	adcq	%rdx, %rbx
	mulq	80(%rsp)
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	-8(%rsp)
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %rdi
	shrdq	$51, %rbx, %rcx
	andq	%r15, %rdi
	leaq	(%rcx,%rcx,8), %rax
	movq	%rdi, 192(%rsp)
	leaq	(%rcx,%rax,2), %rax
	addq	%rax, %r8
	movq	%r8, %r9
	shrq	$51, %r8
	addq	%r8, %r10
	andq	%r15, %r9
	andq	%r10, %r15
	shrq	$51, %r10
	movq	%r9, 88(%rsp)
	leaq	(%r10,%r11), %rcx
	movq	%r15, %r13
	movq	%rdi, %r11
	movq	%r15, 72(%rsp)
	movq	%r9, %rdi
	movabsq	$2251799813685247, %r15
	movq	%rcx, 128(%rsp)
	movq	%rcx, %r14
	movq	104(%rsp), %r12
	movq	%r13, %rsi
	movq	$100, -40(%rsp)
	movq	%r11, %rbp
	.p2align 4,,10
	.p2align 3
.L8:
  lfence
	leaq	(%rsi,%rsi), %rax
	leaq	(%rdi,%rdi), %r11
	movq	%rax, -120(%rsp)
	leaq	0(%rbp,%rbp,8), %rax
	leaq	0(%rbp,%rax,2), %r13
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %rcx
	leaq	(%r13,%r13), %r8
	leaq	(%rcx,%rcx), %rbx
	movq	%rbx, %rax
	mulq	%r12
	movq	%rax, %r9
	movq	%rdi, %rax
	movq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r11, %rax
	adcq	%rdx, %r10
	mulq	%rbp
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	leaq	(%r12,%r12,8), %rax
	movq	%rcx, -104(%rsp)
	adcq	%rdx, %rbx
	leaq	(%r12,%rax,2), %rcx
	movq	%rbx, -96(%rsp)
	movq	%r9, %rbx
	andq	%r15, %rbx
	movq	%rcx, %rax
	movq	%rbx, -88(%rsp)
	mulq	%r12
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, %rdi
	mulq	%r14
	andq	%r15, %rdi
	movq	%rdi, -56(%rsp)
	movq	%rax, %r9
	movq	%rsi, %rax
	movq	%rdx, %r10
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r8, %rax
	addq	%r9, %rsi
	adcq	%r10, %rdi
	mulq	%r12
	addq	%rax, %rsi
	movq	%r12, %rax
	adcq	%rdx, %rdi
	movq	%rsi, %r8
	shrdq	$51, %rbx, %rcx
	movq	%rdi, %r9
	shrq	$51, %rbx
	addq	%rcx, %r8
	adcq	%rbx, %r9
	movq	%r8, %r10
	mulq	%r11
	andq	%r15, %r10
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %r9, %r8
	shrq	$51, %r9
	movq	%r8, %rsi
	movq	%r9, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r12
	movq	%rsi, %rcx
	movq	-104(%rsp), %rsi
	movq	%rdi, %rbx
	andq	%r15, %r12
	shrdq	$51, %rdi, %rcx
	movq	-96(%rsp), %rdi
	shrq	$51, %rbx
	addq	%rcx, %rsi
	movq	%rsi, %rcx
	movq	%rsi, %rbp
	adcq	%rbx, %rdi
	andq	%r15, %rbp
	shrdq	$51, %rdi, %rcx
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %r14
	addq	-88(%rsp), %r14
	movq	%r14, %rbx
	shrq	$51, %r14
	addq	-56(%rsp), %r14
	andq	%r15, %rbx
	movq	%rbx, %rdi
	movq	%r14, %rsi
	shrq	$51, %r14
	andq	%r15, %rsi
	addq	%r10, %r14
	subq	$1, -40(%rsp)
	jne	.L8
  lfence
	movq	%rbx, %r9
	movq	192(%rsp), %rbx
	movq	104(%rsp), %rdi
	movq	%rbp, %r11
	movq	%rsi, %r13
	movq	$50, -40(%rsp)
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %r8
	movq	128(%rsp), %rbx
	leaq	(%rbx,%rbx,8), %rax
	leaq	(%rbx,%rax,2), %rbp
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %r10
	movq	88(%rsp), %rax
	movq	72(%rsp), %rdi
	mulq	%r9
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	leaq	(%rdi,%rdi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rdi,%rax,2), %rax
	mulq	%r11
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	movq	%rax, %rsi
	movq	%rdx, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, -120(%rsp)
	movq	88(%rsp), %rax
	mulq	%r13
	movq	%rax, %rcx
	movq	72(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%rbp, %rax
	movq	72(%rsp), %rbp
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, -104(%rsp)
	andq	%r15, %rsi
	mulq	%r14
	movq	%rsi, -88(%rsp)
	movq	%rdi, -96(%rsp)
	movq	-104(%rsp), %rsi
	movq	-96(%rsp), %rdi
	movq	%rax, %rcx
	movq	128(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r10
	mulq	%r12
	andq	%r15, %r10
	movq	%rax, %rcx
	movq	104(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	128(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	88(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rdx
	adcq	%rbx, %rdi
	andq	%r15, %rdx
	movq	%rdx, %rbp
	mulq	%r11
	movq	%rax, %rcx
	movq	192(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	72(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	104(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	128(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	movq	-88(%rsp), %rsi
	adcq	%rdi, %rbx
	movq	%rcx, %r12
	shrdq	$51, %rbx, %rcx
	andq	%r15, %r12
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-120(%rsp), %rax
	movq	%rax, %r9
	shrq	$51, %rax
	leaq	(%rax,%rsi), %r11
	andq	%r15, %r9
	movq	%r9, %rdi
	andq	%r11, %r15
	shrq	$51, %r11
	movq	%r15, %r13
	leaq	(%r11,%r10), %r14
	movabsq	$2251799813685247, %r15
	movq	%r13, %rsi
	.p2align 4,,10
	.p2align 3
.L9:
  lfence
	leaq	(%rsi,%rsi), %rax
	leaq	(%rdi,%rdi), %r11
	movq	%rax, -120(%rsp)
	leaq	(%r12,%r12,8), %rax
	leaq	(%r12,%rax,2), %r13
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %rcx
	leaq	(%r13,%r13), %r8
	leaq	(%rcx,%rcx), %rbx
	movq	%rbx, %rax
	mulq	%rbp
	movq	%rax, %r9
	movq	%rdi, %rax
	movq	%rdx, %r10
	mulq	%rdi
	addq	%rax, %r9
	movq	%r8, %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	%r11, %rax
	adcq	%rdx, %r10
	mulq	%r12
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	leaq	0(%rbp,%rbp,8), %rax
	movq	%rcx, -104(%rsp)
	adcq	%rdx, %rbx
	leaq	0(%rbp,%rax,2), %rcx
	movq	%rbx, -96(%rsp)
	movq	%r9, %rbx
	andq	%r15, %rbx
	movq	%rcx, %rax
	movq	%rbx, -88(%rsp)
	mulq	%rbp
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%r9, %rcx
	adcq	%r10, %rbx
	movq	%rcx, %rdi
	mulq	%r14
	andq	%r15, %rdi
	movq	%rdi, -56(%rsp)
	movq	%rax, %r9
	movq	%rsi, %rax
	movq	%rdx, %r10
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r8, %rax
	addq	%r9, %rsi
	adcq	%r10, %rdi
	mulq	%rbp
	addq	%rax, %rsi
	movq	%rbp, %rax
	adcq	%rdx, %rdi
	movq	%rsi, %r9
	shrdq	$51, %rbx, %rcx
	movq	%rdi, %r10
	shrq	$51, %rbx
	addq	%rcx, %r9
	adcq	%rbx, %r10
	movq	%r9, %r8
	mulq	%r11
	andq	%r15, %r8
	movq	%rax, %rcx
	movq	-120(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%r12, %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	movq	%r9, %rsi
	movq	%r10, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rbp
	movq	%rsi, %rcx
	movq	-104(%rsp), %rsi
	movq	%rdi, %rbx
	andq	%r15, %rbp
	shrdq	$51, %rdi, %rcx
	movq	-96(%rsp), %rdi
	shrq	$51, %rbx
	addq	%rcx, %rsi
	movq	%rsi, %rcx
	movq	%rsi, %r12
	adcq	%rbx, %rdi
	andq	%r15, %r12
	shrdq	$51, %rdi, %rcx
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %r14
	addq	-88(%rsp), %r14
	movq	%r14, %rbx
	shrq	$51, %r14
	addq	-56(%rsp), %r14
	andq	%r15, %rbx
	movq	%rbx, %rdi
	movq	%r14, %rsi
	shrq	$51, %r14
	andq	%r15, %rsi
	addq	%r8, %r14
	subq	$1, -40(%rsp)
	jne	.L9
  lfence
	movq	24(%rsp), %r11
	movq	56(%rsp), %r10
	movq	%rbx, %r9
	movq	%rsi, %r13
	movq	%r11, %rax
	mulq	%rbx
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	224(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	200(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r11, %rax
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r8
	mulq	%r13
	andq	%r15, %r8
	movq	%rax, %rcx
	movq	-24(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	%r10, %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	200(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, %r10
	movq	%r11, %rax
	mulq	%r14
	movq	%rax, %rcx
	movq	-8(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	-24(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	136(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, -120(%rsp)
	movq	%r11, %rax
	mulq	%rbp
	movq	%rax, %rcx
	movq	80(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	-8(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	-24(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	56(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rsi, %rcx
	adcq	%rdi, %rbx
	movq	%rcx, %rdi
	mulq	%r12
	andq	%r15, %rdi
	movq	%rax, %r11
	movq	152(%rsp), %rax
	movq	%rdx, %r12
	mulq	%r9
	addq	%rax, %r11
	movq	-24(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%rbp
	addq	%rax, %r11
	movq	80(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r13
	addq	%rax, %r11
	movq	-8(%rsp), %rax
	adcq	%rdx, %r12
	mulq	%r14
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	shrdq	$51, %rbx, %rcx
	andq	%r15, %r9
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	%rax, %r8
	movq	-120(%rsp), %rax
	movq	%r8, %rcx
	shrq	$51, %r8
	addq	%r8, %r10
	andq	%r15, %rcx
	movq	%r10, %r8
	shrq	$51, %r10
	leaq	(%r10,%rax), %rsi
	leaq	(%r9,%r9,8), %rax
	andq	%r15, %r8
	leaq	(%rcx,%rcx), %r10
	leaq	(%r8,%r8), %r14
	leaq	(%r9,%rax,2), %r13
	movq	%rcx, %rax
	mulq	%rcx
	leaq	(%r13,%r13), %rbp
	movq	%rax, %rcx
	movq	%rbp, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%rdi
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r11
	andq	%r15, %rax
	movq	%rbx, %r12
	movq	%rax, -88(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%rdi
	movq	%rax, %rcx
	movq	%r8, %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	mulq	%rdi
	movq	%rbx, -96(%rsp)
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	-104(%rsp), %rcx
	movq	%rbx, -120(%rsp)
	movq	-96(%rsp), %rbx
	movq	%rax, %r11
	movq	%r8, %rax
	movq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %r11
	adcq	%rbx, %r12
	movq	%r11, %rbp
	mulq	%r9
	andq	%r15, %rbp
	movq	%rax, %rcx
	movq	%rdi, %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r8
	mulq	%rsi
	andq	%r15, %r8
	movq	%rax, %r11
	movq	%rdi, %rax
	movq	%rdx, %r12
	mulq	%r14
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r9, %rax
	addq	%r11, %rsi
	adcq	%r12, %rdi
	mulq	%r10
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rcx
	movq	%rsi, %r9
	shrdq	$51, %rdi, %rcx
	andq	%r15, %r9
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-88(%rsp), %rax
	movq	%rax, %r11
	shrq	$51, %rax
	addq	-120(%rsp), %rax
	andq	%r15, %r11
	leaq	(%r11,%r11), %r10
	movq	%rax, %rdi
	shrq	$51, %rax
	leaq	(%rax,%rbp), %rsi
	leaq	(%r9,%r9,8), %rax
	andq	%r15, %rdi
	leaq	(%rdi,%rdi), %r14
	leaq	(%r9,%rax,2), %r13
	movq	%rdi, %rax
	leaq	(%r13,%r13), %rbp
	mulq	%rbp
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r8
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r11
	andq	%r15, %rax
	movq	%rbx, %r12
	movq	%rax, -88(%rsp)
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%r8
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	mulq	%r8
	movq	%rbx, -96(%rsp)
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	-104(%rsp), %rcx
	movq	%rbx, -120(%rsp)
	movq	-96(%rsp), %rbx
	movq	%rax, %r11
	movq	%rdi, %rax
	movq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %r11
	movq	%rax, %rdi
	movq	%r13, %rax
	movq	%rdx, %r12
	andq	%r15, %rdi
	mulq	%r9
	movq	%rdi, %rbp
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdi
	mulq	%rsi
	andq	%r15, %rdi
	movq	%rax, %r11
	movq	%r14, %rax
	movq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	shrdq	$51, %rbx, %rcx
	andq	%r15, %r9
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-88(%rsp), %rax
	movq	%rax, %r11
	shrq	$51, %rax
	addq	-120(%rsp), %rax
	andq	%r15, %r11
	leaq	(%r11,%r11), %r10
	movq	%rax, %r8
	shrq	$51, %rax
	leaq	(%rax,%rbp), %rsi
	leaq	(%r9,%r9,8), %rax
	andq	%r15, %r8
	leaq	(%r8,%r8), %r14
	leaq	(%r9,%rax,2), %r13
	movq	%r8, %rax
	leaq	(%r13,%r13), %rbp
	mulq	%rbp
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%rdi
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r11
	andq	%r15, %rax
	movq	%rbx, %r12
	movq	%rax, -88(%rsp)
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%rdi
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	mulq	%rdi
	movq	%rbx, -96(%rsp)
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	-104(%rsp), %rcx
	movq	%rbx, -120(%rsp)
	movq	-96(%rsp), %rbx
	movq	%rax, %r11
	movq	%r8, %rax
	movq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%rax, %r11
	movq	%r13, %rax
	adcq	%rdx, %r12
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %r11
	adcq	%rbx, %r12
	movq	%r11, %rbp
	mulq	%r9
	andq	%r15, %rbp
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r8
	mulq	%rsi
	andq	%r15, %r8
	movq	%rax, %r11
	movq	%r14, %rax
	movq	%rdx, %r12
	mulq	%rdi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r9, %rax
	addq	%r11, %rsi
	adcq	%r12, %rdi
	mulq	%r10
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %rcx
	movq	%rsi, %r9
	shrdq	$51, %rdi, %rcx
	andq	%r15, %r9
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-88(%rsp), %rax
	movq	%rax, %r11
	shrq	$51, %rax
	addq	-120(%rsp), %rax
	andq	%r15, %r11
	leaq	(%r11,%r11), %r10
	movq	%rax, %rdi
	shrq	$51, %rax
	leaq	(%rax,%rbp), %rsi
	leaq	(%r9,%r9,8), %rax
	andq	%r15, %rdi
	leaq	(%rdi,%rdi), %r14
	leaq	(%r9,%rax,2), %r13
	movq	%rdi, %rax
	leaq	(%r13,%r13), %rbp
	mulq	%rbp
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%r8
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r11
	andq	%r15, %rax
	movq	%rbx, %r12
	movq	%rax, -88(%rsp)
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%r8
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rbp, %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	mulq	%r8
	movq	%rbx, -96(%rsp)
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	-104(%rsp), %rcx
	movq	%rbx, -120(%rsp)
	movq	-96(%rsp), %rbx
	movq	%rax, %r11
	movq	%rdi, %rax
	movq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%rsi, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %r11
	movq	%rax, %rdi
	movq	%r13, %rax
	movq	%rdx, %r12
	andq	%r15, %rdi
	mulq	%r9
	movq	%rdi, %rbp
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r11, %rcx
	adcq	%rbx, %rdx
	movq	%r12, %rbx
	shrdq	$51, %r12, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%rsi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %rdi
	mulq	%rsi
	andq	%r15, %rdi
	movq	%rax, %r11
	movq	%r14, %rax
	movq	%rdx, %r12
	mulq	%r8
	addq	%rax, %r11
	movq	%r9, %rax
	adcq	%rdx, %r12
	mulq	%r10
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %r8
	shrdq	$51, %rbx, %rcx
	movq	-120(%rsp), %rbx
	andq	%r15, %r8
	leaq	(%rcx,%rcx,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-88(%rsp), %rax
	movq	%rax, %rcx
	shrq	$51, %rax
	leaq	(%rax,%rbx), %rdx
	andq	%r15, %rcx
	movq	%rdx, %r11
	shrq	$51, %rdx
	andq	%r15, %r11
	leaq	(%rdx,%rbp), %rsi
	leaq	(%rcx,%rcx), %rbp
	leaq	(%r11,%r11), %rax
	movq	%rax, -120(%rsp)
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %r14
	movq	%rcx, %rax
	mulq	%rcx
	leaq	(%r14,%r14), %r13
	movq	%rax, %rcx
	movq	%r13, %rax
	movq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	addq	%rax, %rax
	mulq	%rdi
	addq	%rax, %rcx
	leaq	(%rdi,%rdi,8), %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	andq	%r15, %rcx
	movq	%rcx, -104(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	movq	%rbx, %r10
	movq	%rcx, %rax
	mulq	%rdi
	movq	%rax, %rcx
	movq	%r11, %rax
	movq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r13, %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rcx, %rax
	movq	%r9, %rcx
	adcq	%rbx, %rdx
	movq	%r10, %rbx
	shrdq	$51, %r10, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	movq	%rbx, %r10
	movq	%rcx, %rbx
	andq	%r15, %rbx
	movq	%rbx, -88(%rsp)
	movq	%r10, %rbx
	movq	%rax, %r11
	movq	%r13, %rax
	movq	%rdx, %r12
	mulq	%rdi
	addq	%rax, %r11
	movq	%rbp, %rax
	adcq	%rdx, %r12
	mulq	%rsi
	addq	%r11, %rax
	adcq	%r12, %rdx
	shrq	$51, %rbx
	shrdq	$51, %r10, %rcx
	addq	%rax, %rcx
	movq	%rdi, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r13
	mulq	%rbp
	andq	%r15, %r13
	movq	%rax, %r9
	movq	%r14, %rax
	movq	%rdx, %r10
	mulq	%r8
	movq	-120(%rsp), %r14
	addq	%rax, %r9
	movq	%r14, %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	%r14, %rax
	movq	120(%rsp), %r14
	adcq	%rdx, %rbx
	movq	%rcx, %r10
	mulq	%rdi
	andq	%r15, %r10
	movq	%rax, %r11
	movq	%rsi, %rax
	movq	%rdx, %r12
	mulq	%rsi
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%rbp, %rax
	addq	%r11, %rsi
	adcq	%r12, %rdi
	mulq	%r8
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	movq	%rcx, %rax
	movq	%rbx, %rdx
	movq	40(%rsp), %rbx
	addq	%rsi, %rax
	adcq	%rdi, %rdx
	movq	%rax, %r9
	shrdq	$51, %rdx, %rax
	andq	%r15, %r9
	movq	%rax, %rcx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rcx,%rax,2), %rax
	addq	-104(%rsp), %rax
	movq	%rax, %r11
	shrq	$51, %rax
	addq	-88(%rsp), %rax
	andq	%r15, %r11
	movq	%rax, %rbp
	shrq	$51, %rax
	leaq	(%rax,%r13), %r12
	leaq	(%rbx,%rbx,8), %rax
	andq	%r15, %rbp
	leaq	(%rbx,%rax,2), %r8
	leaq	(%r14,%r14,8), %rax
	leaq	(%r14,%rax,2), %rcx
	movq	%rcx, %rax
	mulq	%r9
	movq	%rax, %rcx
	movq	%r10, %rax
	movq	%rdx, %rbx
	mulq	%r8
	addq	%rax, %rcx
	movq	112(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	184(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	208(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	movq	%rax, %rsi
	movq	%rdx, %rdi
	movq	%r8, %rax
	addq	%rcx, %rsi
	movq	%r14, %r8
	adcq	%rbx, %rdi
	movq	%rsi, %r13
	mulq	%r9
	andq	%r15, %r13
	movq	%rax, %rcx
	movq	208(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r10
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	112(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	184(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	184(%rsp), %rax
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rbx, %rdi
	movq	%rsi, %r14
	mulq	%r10
	andq	%r15, %r14
	movq	%rax, %rcx
	movq	208(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	40(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	112(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	adcq	%rdx, %rbx
	shrdq	$51, %rdi, %rsi
	shrq	$51, %rdi
	addq	%rcx, %rsi
	movq	%rsi, %rax
	adcq	%rbx, %rdi
	andq	%r15, %rax
	movq	%rax, -120(%rsp)
	movq	112(%rsp), %rax
	mulq	%r10
	movq	%rax, %rcx
	movq	184(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r9
	addq	%rax, %rcx
	movq	48(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r11
	addq	%rax, %rcx
	movq	40(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rbp
	addq	%rax, %rcx
	movq	%r8, %rax
	adcq	%rdx, %rbx
	mulq	%r12
	addq	%rcx, %rax
	movq	%rsi, %rcx
	adcq	%rbx, %rdx
	movq	%rdi, %rbx
	shrdq	$51, %rdi, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	112(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	andq	%r15, %rcx
	movq	%rcx, %r8
	movq	%rbx, -96(%rsp)
	movq	-104(%rsp), %rcx
	mulq	%r9
	movq	-96(%rsp), %rbx
	movq	%rax, %rsi
	movq	120(%rsp), %rax
	movq	%rdx, %rdi
	mulq	%r10
	addq	%rax, %rsi
	movq	216(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r11
	addq	%rax, %rsi
	movq	48(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%rbp
	addq	%rax, %rsi
	movq	40(%rsp), %rax
	adcq	%rdx, %rdi
	mulq	%r12
	addq	%rsi, %rax
	adcq	%rdi, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rbp
	shrdq	$51, %rdx, %rax
	andq	%r15, %rbp
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rax
	addq	%r13, %rax
	movq	%rax, %r13
	shrq	$51, %rax
	addq	%rax, %r14
	movq	-120(%rsp), %rax
	andq	%r15, %r13
	movq	%r14, %rsi
	shrq	$51, %r14
	andq	%r15, %rsi
	leaq	(%r14,%rax), %rdi
	leaq	0(%rbp,%rbp,8), %rax
	leaq	0(%rbp,%rax,2), %r11
	leaq	(%rdi,%rdi,8), %rax
	leaq	(%rdi,%rax,2), %r14
	leaq	(%r8,%r8,8), %rax
	leaq	(%r8,%rax,2), %r12
	movq	8(%rsp), %rax
	mulq	%r11
	movq	%rax, %rcx
	movq	168(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	16(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	leaq	(%rsi,%rsi,8), %rax
	adcq	%rdx, %rbx
	leaq	(%rsi,%rax,2), %rax
	mulq	-72(%rsp)
	addq	%rax, %rcx
	movq	176(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r14
	addq	%rax, %rcx
	movq	%rcx, %rax
	adcq	%rdx, %rbx
	movq	%rcx, %r9
	andq	%r15, %rax
	movq	%rbx, %r10
	movq	%rax, -120(%rsp)
	movq	168(%rsp), %rax
	mulq	%r11
	movq	%rax, %rcx
	movq	176(%rsp), %rax
	movq	%rdx, %rbx
	mulq	%r12
	addq	%rax, %rcx
	movq	8(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	16(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	%r14, %rax
	adcq	%rdx, %rbx
	mulq	-72(%rsp)
	addq	%rcx, %rax
	movq	%r9, %rcx
	adcq	%rbx, %rdx
	movq	%r10, %rbx
	shrdq	$51, %r10, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	176(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	andq	%r15, %rcx
	movq	%rbx, -96(%rsp)
	movq	%rcx, %r14
	movq	-96(%rsp), %rbx
	mulq	%r11
	movq	-104(%rsp), %rcx
	movq	%rax, %r9
	movq	%r12, %rax
	movq	-72(%rsp), %r12
	movq	%rdx, %r10
	mulq	%r12
	addq	%rax, %r9
	movq	168(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%rax, %r9
	movq	8(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	16(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rdi
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rax, %rcx
	movq	16(%rsp), %rax
	adcq	%rdx, %rbx
	movq	%rcx, -104(%rsp)
	andq	%r15, %rcx
	movq	%rcx, -88(%rsp)
	movq	%rbx, -96(%rsp)
	mulq	%r8
	movq	-104(%rsp), %rcx
	movq	-96(%rsp), %rbx
	movq	%rax, %r9
	movq	%r11, %rax
	movq	%rdx, %r10
	mulq	%r12
	addq	%rax, %r9
	movq	176(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%r13
	addq	%rax, %r9
	movq	168(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rsi
	addq	%rax, %r9
	movq	8(%rsp), %rax
	adcq	%rdx, %r10
	mulq	%rdi
	addq	%r9, %rax
	adcq	%r10, %rdx
	shrdq	$51, %rbx, %rcx
	shrq	$51, %rbx
	addq	%rcx, %rax
	movq	%rax, %r11
	movq	16(%rsp), %rax
	adcq	%rbx, %rdx
	movq	%rdx, %r12
	mulq	%rbp
	movq	%rax, %r9
	movq	8(%rsp), %rax
	movq	%rdx, %r10
	mulq	%r8
	movq	%rax, %rcx
	movq	-72(%rsp), %rax
	movq	%rdx, %rbx
	addq	%r9, %rcx
	adcq	%r10, %rbx
	mulq	%r13
	addq	%rax, %rcx
	movq	176(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rsi
	addq	%rax, %rcx
	movq	168(%rsp), %rax
	adcq	%rdx, %rbx
	mulq	%rdi
	addq	%rax, %rcx
	movq	%r11, %rax
	adcq	%rdx, %rbx
	movq	%r12, %rdx
	shrdq	$51, %r12, %rax
	shrq	$51, %rdx
	addq	%rcx, %rax
	adcq	%rbx, %rdx
	movq	%rax, %rcx
	movq	%rax, -104(%rsp)
	shrdq	$51, %rdx, %rcx
	movq	%r11, %rax
	xorl	%r10d, %r10d
	leaq	(%rcx,%rcx,8), %rdx
	andq	%r15, %rax
	movq	%rax, %r9
	movq	-104(%rsp), %rax
	leaq	(%rcx,%rdx,2), %rbp
	addq	-120(%rsp), %rbp
	xorl	%edx, %edx
	movq	%rdx, %rbx
	shrq	$51, %rbx
	movq	%rbp, %rdi
	shrq	$51, %rdi
	addq	%r14, %rdi
	movq	%rdi, %r8
	shrq	$51, %r8
	addq	-88(%rsp), %r8
	movq	%r8, %rcx
	shrdq	$51, %rdx, %rcx
	addq	%rcx, %r9
	adcq	%rbx, %r10
	andq	%r15, %rax
	xorl	%r12d, %r12d
	movq	%rax, %r11
	movq	%r9, %rax
	movq	%r10, %rdx
	shrdq	$51, %r10, %rax
	shrq	$51, %rdx
	addq	%rax, %r11
	movl	$19, %eax
	adcq	%rdx, %r12
	movq	%r11, %rcx
	andq	%r15, %rbp
	shrdq	$51, %r12, %rcx
	movq	%r12, %rbx
	mulq	%rcx
	shrq	$51, %rbx
	imulq	$19, %rbx, %rsi
	movq	%rax, %rcx
	movq	%rdx, %rbx
	xorl	%edx, %edx
	addq	%rsi, %rbx
	addq	%rbp, %rcx
	adcq	%rdx, %rbx
	movq	%rcx, %rsi
	andq	%r15, %rdi
	shrdq	$51, %rbx, %rsi
	movq	%rdi, %rax
	movq	%rbx, %rdi
	xorl	%edx, %edx
	shrq	$51, %rdi
	addq	%rax, %rsi
	adcq	%rdx, %rdi
	andq	%r15, %r8
	xorl	%edx, %edx
	movq	%rdi, %rbp
	movq	%rsi, %rdi
	movq	%rsi, -120(%rsp)
	shrdq	$51, %rbp, %rdi
	shrq	$51, %rbp
	movq	%r9, %rsi
	addq	%r8, %rdi
	adcq	%rdx, %rbp
	movq	%rdi, %r8
	andq	%r15, %rsi
	shrdq	$51, %rbp, %r8
	movq	%rbp, %r9
	xorl	%edx, %edx
	shrq	$51, %r9
	addq	%rsi, %r8
	movq	%r11, %rsi
	adcq	%rdx, %r9
	andq	%r15, %rsi
	xorl	%edx, %edx
	movq	%r9, %r10
	movq	%r8, %r9
	movq	%r8, -104(%rsp)
	shrdq	$51, %r10, %r9
	shrq	$51, %r10
	addq	%rsi, %r9
	movl	$19, %esi
	movq	%r9, %r8
	adcq	%rdx, %r10
	andq	%r15, %rcx
	movq	%r8, %rax
	movq	%r10, %rdx
	movq	%rcx, %r11
	shrdq	$51, %r10, %rax
	shrq	$51, %rdx
	xorl	%r12d, %r12d
	movq	%rdi, %rcx
	imulq	$19, %rdx, %r10
	mulq	%rsi
	addq	%r10, %rdx
	addq	$19, %r11
	adcq	$0, %r12
	addq	%rax, %r11
	movq	-120(%rsp), %rax
	adcq	%rdx, %r12
	xorl	%r14d, %r14d
	movq	%r12, %rdx
	andq	%r15, %rax
	shrq	$51, %rdx
	movq	%rax, %r13
	movq	%r11, %rax
	shrdq	$51, %r12, %rax
	addq	%rax, %r13
	movq	-104(%rsp), %rax
	adcq	%rdx, %r14
	movq	%r13, %rsi
	andq	%r15, %rcx
	shrdq	$51, %r14, %rsi
	movq	%r14, %rdi
	xorl	%edx, %edx
	shrq	$51, %rdi
	addq	%rcx, %rsi
	adcq	%rdx, %rdi
	andq	%r15, %rax
	xorl	%ebx, %ebx
	movq	%rax, %rcx
	movq	%rsi, %rax
	movq	%rdi, %rdx
	shrdq	$51, %rdi, %rax
	shrq	$51, %rdx
	movq	%r8, %rdi
	movq	%rsi, -120(%rsp)
	addq	%rax, %rcx
	movl	$19, %esi
	movq	$0, -96(%rsp)
	adcq	%rdx, %rbx
	movq	%rcx, %r8
	andq	%r15, %rdi
	shrdq	$51, %rbx, %r8
	movq	%rbx, %r9
	xorl	%edx, %edx
	movq	$0, -112(%rsp)
	shrq	$51, %r9
	addq	%rdi, %r8
	adcq	%rdx, %r9
	movq	%r8, %rax
	xorl	%r12d, %r12d
	shrdq	$51, %r9, %rax
	movq	%r9, %rdx
	movq	%r9, -80(%rsp)
	xorl	%r10d, %r10d
	shrq	$51, %rdx
	movq	%r8, -88(%rsp)
	imulq	$19, %rdx, %rdi
	mulq	%rsi
	addq	%rdi, %rdx
	movq	%r11, %rdi
	movabsq	$2251799813685229, %r11
	andq	%r15, %rdi
	movq	%rdi, %r9
	movq	%r13, %rdi
	addq	%r11, %r9
	adcq	%r12, %r10
	addq	%r9, %rax
	movabsq	$2251799813685247, %r9
	adcq	%r10, %rdx
	andq	%r15, %rdi
	xorl	%r10d, %r10d
	movq	%rdi, %r11
	xorl	%r12d, %r12d
	movq	%rax, %r13
	addq	%r9, %r11
	movq	-120(%rsp), %rdi
	movq	%rdx, %r14
	adcq	%r10, %r12
	shrq	$51, %r14
	shrdq	$51, %rdx, %r13
	addq	%r11, %r13
	adcq	%r12, %r14
	andq	%r15, %rdi
	xorl	%r12d, %r12d
	movq	%rdi, %rsi
	movq	%r13, %r11
	movq	%r12, %rdi
	addq	%r9, %rsi
	movq	%r14, %r12
	adcq	%r10, %rdi
	shrq	$51, %r12
	shrdq	$51, %r14, %r11
	addq	%rsi, %r11
	adcq	%rdi, %r12
	xorl	%r14d, %r14d
	movq	%r13, %rdi
	andq	%r15, %rcx
	andq	%r15, %rdi
	movq	%r14, %rbx
	addq	%r9, %rcx
	movq	%r11, %r13
	movq	%r12, %r14
	adcq	%r10, %rbx
	shrq	$51, %r14
	movq	%rdi, -104(%rsp)
	shrdq	$51, %r12, %r13
	movq	-96(%rsp), %rdi
	addq	%rcx, %r13
	movq	%r11, %rcx
	adcq	%rbx, %r14
	movq	%r13, %rbx
	andq	%r15, %rcx
	movq	%r14, %rsi
	movq	%rcx, %r13
	movq	%rbx, %r11
	movq	%rsi, %r12
	movq	-104(%rsp), %rsi
	movq	%rbx, %rcx
	movq	352(%rsp), %rbx
	andq	%r15, %rax
	andq	%r15, %rcx
	movq	%rcx, -120(%rsp)
	xorl	%r14d, %r14d
	movq	%r13, %rcx
	movq	%rsi, %rdx
	salq	$51, %rdx
	orq	%rdx, %rax
	movq	%rax, (%rbx)
	movq	%r13, %rax
	movq	%r11, %r13
	shrdq	$13, %rdi, %rsi
	salq	$38, %rax
	movq	%rbx, %rdi
	movq	-120(%rsp), %r11
	orq	%rax, %rsi
	movq	-120(%rsp), %rax
	shrdq	$26, %r14, %rcx
	movq	%rsi, 8(%rbx)
	salq	$25, %rax
	orq	%rax, %rcx
	movq	%rcx, 16(%rdi)
	movq	-88(%rsp), %rcx
	andq	%r15, %rcx
	movq	%rcx, %rax
	addq	%r9, %rax
	shrdq	$51, %r12, %r13
	movq	-112(%rsp), %r12
	addq	%r13, %rax
	andq	%r15, %rax
	shrdq	$39, %r12, %r11
	salq	$12, %rax
	orq	%r11, %rax
	movq	%rax, 24(%rdi)
	addq	$784, %rsp
	.cfi_def_cfa_offset 56
	xorl	%eax, %eax
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.cfi_endproc
.LFE11:
	.size	crypto_scalarmult_lfence, .-crypto_scalarmult_lfence
	.ident	"GCC: (Debian 6.3.0-18+deb9u1) 6.3.0 20170516"
	.section	.note.GNU-stack,"",@progbits
