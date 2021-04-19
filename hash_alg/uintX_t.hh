/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: uintX_t.hh,v 1.9 2005/09/22 07:38:24 kani Exp $
 * $Date: 2005/09/22 07:38:24 $
 * $Revision: 1.9 $
 */

#ifndef __uintX_t_hh__
#define __uintX_t_hh__

#include <iostream>
#include <sys/types.h>
#include <stdexcept>

// -------
// uintX_t
// -------
class
uintX_t {
  private:
    // no member.

  protected:
    static const size_t default_bitsiz = 128;
    typedef unsigned int calcregs_t;
    typedef calcregs_t srcregs_t;
    size_t calcbits;
    size_t bitsiz;
    size_t cnt_bufsiz;
    calcregs_t* cnt; // data buffer body.
    char* hexstr;
    char* binstr;
    char* decstr;
    uintX_t* retv_tmp;

  protected:
    void constructor(size_t);
    size_t r_idx(size_t);
    void replace_tmp();
    void replace_tmp(srcregs_t);

  public:
    enum STR_MODE {NO_HEADER_SMALL_CAPS,
		   NO_HEADER_LERGE_CAPS,
		   HEADER_SMALL_CAPS,
		   HEADER_LERGE_CAPS
    };

  public:
    uintX_t(srcregs_t initnum = 0, size_t initbitsiz = default_bitsiz);
    uintX_t(uintX_t&);
    ~uintX_t();

    uintX_t& reset();
    uintX_t& set(uintX_t&);
    uintX_t& set(srcregs_t);
    uintX_t& set_hexstr(const char*);
    uintX_t& set_binstr(const char*);
    uintX_t& set_decstr(const char*);

    uintX_t& operator =(uintX_t);
    uintX_t& operator =(srcregs_t);
    uintX_t& operator =(const char*);

    int operator <(uintX_t&);
    int operator >(uintX_t&);
    int operator ==(uintX_t&);
    int operator !=(uintX_t&);
    int operator <=(uintX_t&);
    int operator >=(uintX_t&);

    uintX_t& operator ++();
    uintX_t& operator ++(int);
    uintX_t& operator --();
    uintX_t& operator --(int);

    uintX_t& operator +=(uintX_t&);
    uintX_t& operator +=(srcregs_t);
    uintX_t& operator +(uintX_t&);
    uintX_t& operator +(srcregs_t);

    uintX_t& operator -=(uintX_t&);
    uintX_t& operator -=(srcregs_t);
    uintX_t& operator -(uintX_t&);
    uintX_t& operator -(srcregs_t);

    uintX_t& operator *=(uintX_t&);
    uintX_t& operator *=(srcregs_t);
    uintX_t& operator *(uintX_t&);
    uintX_t& operator *(srcregs_t);

    uintX_t& operator /=(uintX_t&);
    uintX_t& operator /=(srcregs_t);
    uintX_t& operator /(uintX_t&);
    uintX_t& operator /(srcregs_t);

    uintX_t& operator %=(uintX_t&);
    uintX_t& operator %=(srcregs_t);
    uintX_t& operator %(uintX_t&);
    uintX_t& operator %(srcregs_t);

    uintX_t& BitSet(size_t, int);

    uintX_t& operator <<=(size_t);
    uintX_t& operator <<(size_t);

    uintX_t& operator >>=(size_t);
    uintX_t& operator >>(size_t);

    uintX_t& operator |=(uintX_t&);
    uintX_t& operator |=(srcregs_t);
    uintX_t& operator |(uintX_t&);
    uintX_t& operator |(srcregs_t);

    uintX_t& operator &=(uintX_t&);
    uintX_t& operator &=(srcregs_t);
    uintX_t& operator &(uintX_t&);
    uintX_t& operator &(srcregs_t);

    uintX_t& operator ^=(uintX_t&);
    uintX_t& operator ^=(srcregs_t);
    uintX_t& operator ^(uintX_t&);
    uintX_t& operator ^(srcregs_t);

    const char* gethexdstr(STR_MODE mod = NO_HEADER_SMALL_CAPS);
    const char* getbinstr();
    const char* getdecstr(int sep_pos = 0, const char sep_chr = ',');
    friend std::ostream& operator <<(std::ostream&, uintX_t&);

    unsigned int operator [](size_t);
    size_t bytesize();
    size_t blocksize();
    size_t regsbitsize();
};

#endif // uintX_t.hh
