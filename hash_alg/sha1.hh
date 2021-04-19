/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha1.hh,v 1.3 2005/09/20 08:34:24 kani Exp $
 * $Date: 2005/09/20 08:34:24 $
 * $Revision: 1.3 $
 */

#ifndef __sha1_hh_defined__
#define __sha1_hh_defined__

#include <sha_base.hh>

class
sha1 : public sha_base {
private:
    uint32_t* digest; // 256-bits message digest

private:
protected:
    void proc_init();
    void proc_hash(unsigned char*);
    void proc_copy_digest();
public:
    sha1();
    ~sha1();
};

#endif
