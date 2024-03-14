#pragma once

#include <linux/kernel.h>

#define KHOOK_F_NOREF		(1UL << 0)	// don't do auto ref-count

typedef struct {
	void			*fn;		// handler fn address
	struct {
		const char	*name;		// target symbol name
		char		*addr;		// target symbol addr (see khook_lookup_name)
	} target;
	void			*orig;		// original fn call wrapper
	void			*stub;		// target fn call wrapper
	unsigned long		flags;		// hook engine options (flags)
	unsigned long		nbytes;
	atomic_t		use_count;
} khook_t;

#define KHOOK_(t, f)							\
	static inline typeof(t) khook_##t; /* forward decl */		\
	static void khook_##t##_orig(void) {				\
		asm(".rept 0x10\n.byte 0\n.endr\n");			\
	}								\
	static void khook_##t##_stub(void) {				\
		asm(".rept 0x80\n.byte 0\n.endr\n");			\
	}								\
	khook_t								\
	__attribute__((unused))						\
	__attribute__((aligned(1)))					\
	__attribute__((section(".data.khook")))				\
	KHOOK_##t = {							\
		.fn = khook_##t,					\
		.target.name = #t,					\
		.orig = khook_##t##_orig,				\
		.stub = khook_##t##_stub,				\
		.flags = f,						\
	}

#define KHOOK(t)							\
	KHOOK_(t, 0)
#define KHOOK_EXT(r, t, ...)						\
	extern r t(__VA_ARGS__);					\
	KHOOK_(t, 0)

#define KHOOK_NOREF(t)							\
	KHOOK_(t, KHOOK_F_NOREF)
#define KHOOK_NOREF_EXT(r, t, ...)					\
	extern r t(__VA_ARGS__);					\
	KHOOK_(t, KHOOK_F_NOREF)

#define KHOOK_ORIGIN(t, ...)						\
	((typeof(t) *)KHOOK_##t.orig)(__VA_ARGS__)

typedef unsigned long (*khook_lookup_t)(const char *);
extern unsigned long khook_lookup_name(const char *);

extern int khook_init(khook_lookup_t);
extern void khook_cleanup(void);

extern long khook_write_kernel(long (*)(void *), void *);
