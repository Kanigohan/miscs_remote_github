/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha224.hh,v 1.1 2005/09/20 05:08:01 kani Exp $
 * $Date: 2005/09/20 05:08:01 $
 * $Revision: 1.1 $
 */

#ifndef __sha224_hh_defined__
#define __sha224_hh_defined__

#include <sha256.hh>

class
sha224 : public sha256 {
private:
private:
protected:
    void proc_init();
    void proc_copy_digest();
public:
    sha224();
    ~sha224();
};
#endif
