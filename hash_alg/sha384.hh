/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha384.hh,v 1.1 2005/09/20 01:49:09 kani Exp $
 * $Date: 2005/09/20 01:49:09 $
 * $Revision: 1.1 $
 */

#ifndef __sha384_hh_defined__
#define __sha384_hh_defined__

#include <sha512.hh>

class
sha384 : public sha512 {
private:
private:
protected:
    void proc_init();
    void proc_copy_digest();
public:
    sha384();
    ~sha384();
};
#endif
