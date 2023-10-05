#
# Hooking of function with more than N arguments requires us to
# make a local copy of all arguments starting from N as they are
# passed through the stack as per the ABI.
#
# On the Intel 386, the regparm attribute causes the compiler to
# pass up to number integer arguments in registers EAX, EDX, and
# ECX instead of on the stack. Functions that take a variable number
# of arguments will continue to be passed all of their arguments
# on the stack.
#
	
.macro CALL_COPY_N_ARGS n
#ifdef __x86_64__
	sub $(\n * 8), %rsp
	.set i, 0
	.rept \n
		mov ((\n + i + 1) * 8)(%rsp), %rax
		mov %rax, (i * 8)(%rsp)
		.set i, i + 1
	.endr
	movabs $0x7a7a7a7a7a7a7a7a, %rax
	call *%rax
	add $(\n * 8), %rsp
#else
	sub $(\n * 4), %esp
	.set i, 0
	.rept \n
		mov ((\n + i + 1) * 4)(%esp), %ebx
		mov %ebx, (i * 4)(%esp)
		.set i, i + 1
	.endr
	mov $0x7a7a7a7a, %ebx
	call *%ebx
	add $(\n * 4), %esp
#endif
.endm

#
# KHOOK_STUB_hook
#

.global KHOOK_STUB_hook
.global KHOOK_STUB_hook_end

KHOOK_STUB_hook:
#ifdef __x86_64__
	lock incl 0x7b7b7b7b(%rip)
	CALL_COPY_N_ARGS 8
	lock decl 0x7b7b7b7b(%rip)
#else
	lock incl (0x7b7b7b7b)
	CALL_COPY_N_ARGS 8
	lock decl (0x7b7b7b7b)
#endif
	ret

KHOOK_STUB_hook_end:
	ret

#
# KHOOK_STUB_hook_noref
#

.global KHOOK_STUB_hook_noref
.global KHOOK_STUB_hook_noref_end

KHOOK_STUB_hook_noref:
	CALL_COPY_N_ARGS 8
	ret

KHOOK_STUB_hook_noref_end:
	ret
