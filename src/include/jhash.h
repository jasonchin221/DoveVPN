#ifndef _LINUX_JHASH_H
#define _LINUX_JHASH_H

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */
#include "dv_types.h"

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((dv_u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL		0xdeadbeef

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate 
 * @shift: bits to roll   
 */
static inline dv_u32 rol32(dv_u32 word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}


struct __una_u16 { dv_u16 x; } __attribute__ ((__packed__));
struct __una_u32 { dv_u32 x; } __attribute__ ((__packed__));
struct __una_u64 { dv_u64 x; } __attribute__ ((__packed__));

static inline dv_u16 __get_unaligned_cpu16(const void *p)
{
    const struct __una_u16 *ptr = (const struct __una_u16 *)p;
    return ptr->x;
}

static inline dv_u32 __get_unaligned_cpu32(const void *p)
{
    const struct __una_u32 *ptr = (const struct __una_u32 *)p;
    return ptr->x;
}

static inline dv_u64 __get_unaligned_cpu64(const void *p)
{
    const struct __una_u64 *ptr = (const struct __una_u64 *)p;
    return ptr->x;
}

static inline void __put_unaligned_cpu16(dv_u16 val, void *p)
{
    struct __una_u16 *ptr = (struct __una_u16 *)p;
    ptr->x = val;
}

static inline void __put_unaligned_cpu32(dv_u32 val, void *p)
{
    struct __una_u32 *ptr = (struct __una_u32 *)p;
    ptr->x = val;
}

static inline void __put_unaligned_cpu64(dv_u64 val, void *p)
{
    struct __una_u64 *ptr = (struct __una_u64 *)p;
    ptr->x = val;
}

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline dv_u32 jhash(const void *key, dv_u32 length, dv_u32 initval)
{
	dv_u32 a, b, c;
	const dv_u8 *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);
		b += __get_unaligned_cpu32(k + 4);
		c += __get_unaligned_cpu32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	/* All the case statements fall through */
	switch (length) {
	case 12: c += (dv_u32)k[11]<<24;
	case 11: c += (dv_u32)k[10]<<16;
	case 10: c += (dv_u32)k[9]<<8;
	case 9:  c += k[8];
	case 8:  b += (dv_u32)k[7]<<24;
	case 7:  b += (dv_u32)k[6]<<16;
	case 6:  b += (dv_u32)k[5]<<8;
	case 5:  b += k[4];
	case 4:  a += (dv_u32)k[3]<<24;
	case 3:  a += (dv_u32)k[2]<<16;
	case 2:  a += (dv_u32)k[1]<<8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

/* jhash2 - hash an array of dv_u32's
 * @k: the key which must be an array of dv_u32's
 * @length: the number of dv_u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline dv_u32 jhash2(const dv_u32 *k, dv_u32 length, dv_u32 initval)
{
	dv_u32 a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + (length<<2) + initval;

	/* Handle most of the key */
	while (length > 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		__jhash_mix(a, b, c);
		length -= 3;
		k += 3;
	}

	/* Handle the last 3 dv_u32's: all the case statements fall through */
	switch (length) {
	case 3: c += k[2];
	case 2: b += k[1];
	case 1: a += k[0];
		__jhash_final(a, b, c);
	case 0:	/* Nothing left to add */
		break;
	}

	return c;
}


/* jhash_3words - hash exactly 3, 2 or 1 word(s) */
static inline dv_u32 jhash_3words(dv_u32 a, dv_u32 b, dv_u32 c, dv_u32 initval)
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

static inline dv_u32 jhash_2words(dv_u32 a, dv_u32 b, dv_u32 initval)
{
	return jhash_3words(a, b, 0, initval);
}

static inline dv_u32 jhash_1word(dv_u32 a, dv_u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}

#endif /* _LINUX_JHASH_H */
