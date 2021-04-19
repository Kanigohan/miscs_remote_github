/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: md5.hh,v 1.3 2005/09/22 03:41:10 kani Exp $
 * $Date: 2005/09/22 03:41:10 $
 * $Revision: &
 */

#ifndef __md5_hh_defined__
#define __md5_hh_defined__

#include <sha_base.hh>

class
md5 : public sha_base {
private:
    uint32_t* digest; // 256-bits message digest
private:
    uint32_t
    F(uint32_t x, uint32_t y, uint32_t z) {
	return (x & y) | (~x & z);
    };

    uint32_t
    G(uint32_t x, uint32_t y, uint32_t z) {
	return (x & z) | (y & ~z);
    };

    uint32_t
    H(uint32_t x, uint32_t y, uint32_t z) {
	return x ^ y ^ z;
    };

    uint32_t
    I(uint32_t x, uint32_t y, uint32_t z) {
	return y ^ (x | ~z);
    };

// --------------------------------------------
    template <class T>
    void
    bytes2block(unsigned char* src, T& dst) {
#if BYTEORDER == BIG_ENDIAN
	endian_swap(src, dst);
#else
	memcpy(&dst, src, sizeof(T));
#endif
    };

// ---------------------------------------------
    template <class T>
    void
    block2bytes(T src, unsigned char* dst) {
#if BYTEORDER == BIG_ENDIAN
	endian_swap(src, dst);
#else
	memcpy(dst, &src, sizeof(T));
#endif
    };

protected:
    void proc_init();
    void proc_hash(unsigned char*);
    void proc_message_padding();
    void proc_copy_digest();
public:
    md5();
    ~md5();
};

#endif
