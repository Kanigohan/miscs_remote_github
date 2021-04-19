/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha512.hh,v 1.8 2005/09/20 08:34:24 kani Exp $
 * $Date: 2005/09/20 08:34:24 $
 * $Revision: 1.8 $
 */

#ifndef __sha512_hh_defined__
#define __sha512_hh_defined__

#include <sha_base.hh>

class
sha512 : public sha_base {
protected:
    uint64_t* digest; // 512-bits message digest

private:
    inline
    uint64_t
    SIGMA0(uint64_t x) {
	return ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39);
    };

    inline
    uint64_t
    SIGMA1(uint64_t x) {
	return ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41);
    };

    inline
    uint64_t
    sigma0(uint64_t x) {
	return ROTR(x, 1) ^ ROTR(x, 8) ^ SHR(x, 7);
    };

    inline
    uint64_t
    sigma1(uint64_t x) {
	return ROTR(x, 19) ^ ROTR(x, 61) ^ SHR(x, 6);
    };

protected:
    virtual void proc_init();
    virtual void proc_hash(unsigned char*);
    virtual void proc_copy_digest();
public:
    sha512();
    ~sha512();
};
#endif
