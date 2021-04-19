/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha256.hh,v 1.3 2005/09/20 08:34:24 kani Exp $
 * $Date: 2005/09/20 08:34:24 $
 * $Revision: 1.3 $
 */

#ifndef __sha256_hh_defined__
#define __sha256_hh_defined__

#include <sha_base.hh>

class
sha256 : public sha_base {
protected:
    uint32_t* digest; // 256-bits message digest

private:
    inline
    uint32_t
    SIGMA0(uint32_t x) {
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    };

    inline
    uint32_t
    SIGMA1(uint32_t x) {
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    };

    inline
    uint32_t
    sigma0(uint32_t x) {
	return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
    };

    inline
    uint32_t
    sigma1(uint32_t x) {
	return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
    };

protected:
    virtual void proc_init();
    virtual void proc_hash(unsigned char*);
    virtual void proc_copy_digest();
public:
    sha256();
    ~sha256();
};
#endif
