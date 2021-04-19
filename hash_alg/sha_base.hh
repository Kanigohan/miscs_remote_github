/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha_base.hh,v 1.14 2005/09/22 09:30:33 kani Exp $
 * $Date: 2005/09/22 09:30:33 $
 * $Revision: 1.14 $
 */

#ifndef __sha_base_hh_defined__
#define __sha_base_hh_defined__

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string.h>
#include <sys/types.h>
#include <machine/endian.h>
#include <uintX_t.hh>

class
sha_base {
private:
    static const size_t READBLOCK = 1024;
protected:
    char* alg_name;
    size_t max_message_bits;
    size_t digest_bits;
    size_t digest_bytes;
    size_t digest_size;
    size_t digest_hexstr_bytes;
    unsigned char* digest_hexstr;
    unsigned char* message_digest;

    size_t block_bits;
    size_t block_bytes;
    size_t block_size;
    size_t last_surplus_bytes;
    unsigned char* block_buffer; // 512-bits hash proc buffer
    uintX_t* cnt; // 64-bits message bits counter

protected:
// ------------------------------------------
    template <class T>
    inline T ROTL(T x, int n) {
	//return (x << n) | (x >> ((sizeof(T) << 3) - n));
	return (x << n) | (x >> ((sizeof(T) * 8) - n));
    };

// ------------------------------------------
    template <class T>
    inline T ROTR(T x, int n) {
	//return (x >> n) | (x << ((sizeof(T) << 3) - n));
	return (x >> n) | (x << ((sizeof(T) * 8) - n));
    };

// ------------------------------------------
    template <class T>
    inline T SHL(T x, int n) {
	return (x << n);
    };

// ------------------------------------------
    template <class T>
    inline T SHR(T x, int n) {
	return (x >> n);
    };

// ------------------------------------------
    template <class T>
    inline T Ch(T x, T y, T z) {
	return (x & y) ^ (~x & z);
    };

// ------------------------------------------
    template <class T>
    inline T Maj(T x, T y, T z) {
	return (x & y) ^ (x & z) ^ (y & z);
    };

// ------------------------------------------
    template <class T>
    inline T Parity(T x, T y, T z) {
	return x ^ y ^ z;
    };

// ------------------------------------------
    template <class T>
    T&
    endian_swap(unsigned char* src, T& dst) {
	size_t end = sizeof(T);
	size_t i = 0;
	int shift = (end << 3) - 8;
	dst = 0;
	while (i < end) {
	    dst |= (T)src[i++] << shift;
	    shift -= 8;
	}
	return dst;
    };

// ------------------------------------------
    template <class T>
    unsigned char*
    endian_swap(T src, unsigned char* dst) {
	size_t end = sizeof(T);
	size_t i = 0;
	int shift = (end << 3) - 8;
	while (i < end) {
	    dst[i++] = (src >> shift) & 0xff;
	    shift -= 8;
	}
	return dst;
    };

// --------------------------------------------
    template <class T>
    inline void
    bytes2block(unsigned char* src, T& dst) {
#if BYTEORDER == BIG_ENDIAN
	memcpy(&dst, src, sizeof(T));
#else
	endian_swap(src, dst);
#endif
    };

// ---------------------------------------------
    template <class T>
    inline void
    block2bytes(T src, unsigned char* dst) {
#if BYTEORDER == BIG_ENDIAN
	memcpy(dst, &src, sizeof(T));
#else
	endian_swap(src, dst);
#endif
    };

// ---------------------------------------------
    template <class T>
    void
    block_clear(T* ptr, size_t siz) {
	for (size_t i = 0; i < siz; i++) {
	    ptr[i] = (T)0;
	}
    };

protected:
    virtual void proc_hash(unsigned char*) = 0;
    virtual void proc_message_padding();
    virtual void proc_copy_digest() = 0;
    template <class pT> void release_ptr(pT p) {
	if (*p) {
	    delete *p;
	    *p = NULL;
	}
    };
public:
    sha_base();
    virtual ~sha_base();
    virtual void proc_init() = 0;
    virtual void proc_update(unsigned char*, size_t);
    virtual void proc_final();
    const unsigned char* proc_2hexstr();
    const unsigned char* proc_data(const char* str);
    const unsigned char* proc_file(const char*);
    const unsigned char* proc_filechunk(const char*, off_t, off_t);
    const char* algorythm_name();
    const size_t digest_byte_length();
};
#endif
