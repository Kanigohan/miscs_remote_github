/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: uintX_t.cc,v 1.9 2005/09/22 07:38:24 kani Exp $
 * $Date: 2005/09/22 07:38:24 $
 * $Revision: 1.9 $
 */

#include <uintX_t.hh>

using namespace std;

// class "uintX_t"
// ----------------------------------

// local function.
// ----------------------------------
inline
size_t
uintX_t::r_idx(size_t idx) {
    return cnt_bufsiz - idx - 1;
}

// ----------------------------------
void
uintX_t::constructor(size_t siz) {
    switch (siz) {
	case 64:
	case 128:
	case 256:
	case 512:
	case 1024:
	case 2084:
	case 4096:
	    bitsiz = siz;
	    break;
	default:
	    bitsiz = default_bitsiz;
    }
    calcbits = sizeof(calcregs_t) * 8;
    cnt_bufsiz = bitsiz / calcbits;
    cnt = new calcregs_t[cnt_bufsiz];
    hexstr = new char[bitsiz / 4 + cnt_bufsiz + 3];
    binstr = new char[bitsiz / 4 + bitsiz + 1];
    decstr = new char[bitsiz * 2 + 1];
    retv_tmp = NULL;
}

// ----------------------------------
void
uintX_t::replace_tmp() {
    if (retv_tmp != NULL) {
	delete retv_tmp;
	retv_tmp = NULL;
    }
    if (retv_tmp == NULL) {
	retv_tmp = new uintX_t(*this);
    }
}

// ----------------------------------
void
uintX_t::replace_tmp(srcregs_t src) {
    if (retv_tmp != NULL) {
	delete retv_tmp;
	retv_tmp = NULL;
    }
    if (retv_tmp == NULL) {
	retv_tmp = new uintX_t(src, bitsiz);
    }
}

// constructor. destructor.
// ----------------------------------
uintX_t::uintX_t(srcregs_t initnum, size_t initbitsiz) {
    constructor(initbitsiz);
    set(initnum);
}

// ----------------------------------
uintX_t::uintX_t(uintX_t& src) {
    constructor(src.bitsiz);
    set(src);
}

// ----------------------------------
uintX_t::~uintX_t() {
    if (cnt != NULL) {
	delete cnt;
	cnt = NULL;
    }
    if (hexstr != NULL) {
	delete hexstr;
	hexstr = NULL;
    }
    if (binstr != NULL) {
	delete binstr;
	binstr = NULL;
    }
    if (decstr != NULL) {
	delete decstr;
	decstr = NULL;
    }
    if (retv_tmp != NULL) {
	delete retv_tmp;
	retv_tmp = NULL;
    }
}


// substitute function.
// ----------------------------------
uintX_t&
uintX_t::reset() {
    memset(cnt, 0, sizeof(calcregs_t)*cnt_bufsiz);
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::set(uintX_t& src) {
    size_t idx = 0;

    if (cnt_bufsiz > src.cnt_bufsiz) {
	while (idx < src.cnt_bufsiz) {
	    cnt[idx] = src.cnt[idx];
	    idx++;
	}
	while (idx < cnt_bufsiz) {
	    cnt[idx] = 0;
	    idx++;
	}
    }
    else {
	while (idx < cnt_bufsiz) {
	    cnt[idx] = src.cnt[idx];
	    idx++;
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::set(srcregs_t src) {
    size_t idx = 0;
    size_t sft;

    reset();
    while (idx < cnt_bufsiz) {
	sft = idx * calcbits;
	if (sft >= (sizeof(srcregs_t) * 8)) {
	    break;
	}
	cnt[idx++] = (calcregs_t)(src >> sft);
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::set_hexstr(const char* hexd_str) {
    size_t len = strlen(hexd_str);
    size_t strcnt = 0;
    size_t idx = 0;
    size_t sft = 0;
    calcregs_t buf;
    char cbuf;

    reset();
    while (strcnt < len) {
	cbuf = hexd_str[len-strcnt-1];
	if (cbuf >= 'a' && cbuf <= 'f') {
	    buf = 10 + cbuf - 'a';
	}
	else if (cbuf >= 'A' && cbuf <= 'F') {
	    buf = 10 + cbuf - 'A';
	}
	else if (cbuf >= '0' && cbuf <= '9') {
	    buf = cbuf - '0';
	}
	else {
	    buf = 0;
	}
	cnt[idx] |= buf << sft;
	sft += 4;
	if (sft == calcbits) {
	    idx++;
	    sft = 0;
	    if (idx >= cnt_bufsiz) {
		break;
	    }
	}
	strcnt++;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::set_binstr(const char* bin_str) {
    size_t len = strlen(bin_str);
    size_t strcnt = 0;
    size_t idx = 0;
    size_t sft = 0;
    calcregs_t buf;
    char cbuf;

    reset();
    while (strcnt < len) {
	cbuf = bin_str[len-strcnt-1];
	if (cbuf != '0') {
	    buf = 1;
	}
	else {
	    buf = 0;
	}
	cnt[idx] |= buf << sft;
	sft++;
	if (sft == calcbits) {
	    idx++;
	    sft = 0;
	}
	strcnt++;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::set_decstr(const char*) {
    // un mount function.
    return *this;
}

// subsutitute operator.
// ----------------------------------
uintX_t&
uintX_t::operator =(uintX_t src) {
    return set(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator =(srcregs_t src) {
    return set(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator =(const char* hexd_str) {
    return set_hexstr(hexd_str);
}


// compare operator.
// ----------------------------------
int
uintX_t::operator <(uintX_t& src) {
    size_t idx = 0;
    size_t ridx;

    if (cnt_bufsiz < src.cnt_bufsiz) {
	for (idx = src.cnt_bufsiz - 1;
	     idx > cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 1;
	    }
	}
    }
    else if (cnt_bufsiz > src.cnt_bufsiz) {
	for (idx = cnt_bufsiz - 1;
	     idx > src.cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 0;
	    }
	}
    }
    else {
	for (idx = 0; idx < cnt_bufsiz; idx++) {
	    ridx = r_idx(idx);
	    if (cnt[ridx] > src.cnt[ridx]) {
		return 0;
	    }
	    else if (cnt[ridx] == src.cnt[ridx]) {
		// nop
	    }
	    else {
		return 1;
	    }
	}
    }
    return 0;
}

// ----------------------------------
int
uintX_t::operator >(uintX_t& src) {
    size_t idx = 0;
    size_t ridx;

    if (cnt_bufsiz < src.cnt_bufsiz) {
	for (idx = src.cnt_bufsiz - 1;
	     idx > cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 0;
	    }
	}
    }
    else if (cnt_bufsiz > src.cnt_bufsiz) {
	for (idx = cnt_bufsiz - 1;
	     idx > src.cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 1;
	    }
	}
    }
    else {
	for (idx = 0; idx < cnt_bufsiz; idx++) {
	    ridx = r_idx(idx);
	    if (cnt[ridx] < src.cnt[ridx]) {
		return 0;
	    }
	    else if (cnt[ridx] == src.cnt[ridx]) {
		// nop
	    }
	    else {
		return 1;
	    }
	}
    }
    return 0;
}

// ----------------------------------
int
uintX_t::operator ==(uintX_t& src) {
    size_t idx = 0;
    size_t ridx;

    if (cnt_bufsiz < src.cnt_bufsiz) {
	for (idx = src.cnt_bufsiz - 1;
	     idx > cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 0;
	    }
	}
    }
    else if (cnt_bufsiz > src.cnt_bufsiz) {
	for (idx = cnt_bufsiz - 1;
	     idx > src.cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 0;
	    }
	}
    }
    else {
	for (idx = 0; idx < cnt_bufsiz; idx++) {
	    ridx = r_idx(idx);
	    if (cnt[ridx] != src.cnt[ridx]) {
		return 0;
	    }
	}
    }
    return 1;
}

// ----------------------------------
int
uintX_t::operator !=(uintX_t& src) {
    size_t idx = 0;
    size_t ridx;

    if (cnt_bufsiz < src.cnt_bufsiz) {
	for (idx = src.cnt_bufsiz - 1;
	     idx > cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 1;
	    }
	}
    }
    else if (cnt_bufsiz > src.cnt_bufsiz) {
	for (idx = cnt_bufsiz - 1;
	     idx > src.cnt_bufsiz;
	     idx--) {
	    if (src.cnt[idx] != 0) {
		return 1;
	    }
	}
    }
    else {
	for (idx = 0; idx < cnt_bufsiz; idx++) {
	    ridx = r_idx(idx);
	    if (cnt[ridx] != src.cnt[ridx]) {
		return 1;
	    }
	}
    }
    return 0;
}

// ----------------------------------
int
uintX_t::operator <=(uintX_t& src) {
    return operator ==(src) || operator <(src);
}

// ----------------------------------
int
uintX_t::operator >=(uintX_t& src) {
    return operator ==(src) || operator >(src);
}


// calclation operator.
// ----------------------------------
uintX_t&
uintX_t::operator ++() {
    size_t idx = 0;

    while (idx < cnt_bufsiz) {
	cnt[idx]++;
	if (cnt[idx] != 0) {
	    break;
	}
	else {
	    // carry over;
	}
	idx++;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator ++(int) {
    replace_tmp();
    operator ++();
    return *retv_tmp;
}

// ----------------------------------
uintX_t&
uintX_t::operator --() {
    size_t idx = 0;
    calcregs_t buf;

    while (idx < cnt_bufsiz) {
	buf = cnt[idx]--;
	if (cnt[idx] < buf) {
	    break;
	}
	else {
	    // digit fall.
	}
	idx++;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator --(int) {
    replace_tmp();
    operator --();
    return *retv_tmp;
}

// ----------------------------------
uintX_t&
uintX_t::operator +=(uintX_t& src) {
    size_t idx = 0;
    calcregs_t buf;
    int carry_over = 0;
    uintX_t* tmp;

    if (this == &src) {
	tmp = new uintX_t(src);
    }
    else {
	tmp = &src;
    }
    while (idx < cnt_bufsiz) {
	if (carry_over) {
	    cnt[idx]++;
	    if (cnt[idx] == 0) {
		carry_over = 1;
	    }
	    else {
		carry_over = 0;
	    }
	}
	buf = cnt[idx];
	cnt[idx] += tmp->cnt[idx];
	if (cnt[idx] < buf) {
	    carry_over = 1;
	}
	idx++;
    }
    if (this == &src) {
	delete tmp;
	tmp = NULL;
    }
    return *this;
}

// ----------------------------------
/*
uintX_t&
uintX_t::operator +=(srcregs_t src) {
    uintX_t* tmp = new uintX_t(src, bitsiz);
    operator +=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}
*/
uintX_t&
uintX_t::operator +=(srcregs_t src) {
    calcregs_t t = cnt[0];
    size_t i = 1;
    cnt[0] += src;
    if (t > cnt[0]) {
	while (i < cnt_bufsiz) {
	    cnt[i]++;
	    if (cnt[i] == 0) {
		i++;
	    }
	    else {
		break;
	    }
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator +(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator +=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator +(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator +=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator -=(uintX_t& src) {
    size_t idx = 0;
    calcregs_t buf;
    int digit_fall = 0;
    uintX_t* tmp;

    if (this == &src) {
	tmp = new uintX_t(src);
    }
    else {
	tmp = &src;
    }

    while (idx < cnt_bufsiz) {
	if (digit_fall) {
	    buf = cnt[idx]--;
	    if (cnt[idx] > buf) {
		digit_fall = 1;
	    }
	    else {
		digit_fall = 0;
	    }
	}
	buf = cnt[idx];
	cnt[idx] -= tmp->cnt[idx];
	if (cnt[idx] > buf) {
	    digit_fall = 1;
	}
	idx++;
    }
    if (this == &src) {
	delete tmp;
	tmp = NULL;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator -=(srcregs_t src) {
    uintX_t* tmp = new uintX_t(src, bitsiz);
    operator -=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator -(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator -=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator -(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator -=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator *=(uintX_t& mul) {
    size_t idx1, idx2, idx3;
    uintX_t* dst = new uintX_t(mul);
    uintX_t* src = new uintX_t(*this);
    calcregs_t buf;
    calcregs_t carry = 0;
    calcregs_t calc[cnt_bufsiz*2];
    union {
	uint64_t ui64;
	uint32_t ui32[2];
    } regs;
    int carry_over = 0;

    reset();
    memset(calc, 0, sizeof(calcregs_t) * cnt_bufsiz * 2);
    for (idx1 = 0; idx1 < src->cnt_bufsiz; idx1++) {
	carry_over = 0;
	for (idx2 = 0; idx2 < dst->cnt_bufsiz; idx2++) {
	    idx3 = idx1 + idx2;
	    if (carry_over) {
		calc[idx3]++;
		if (calc[idx3] == 0) {
		    carry_over = 1;
		}
		else { 
		    carry_over = 0;
		}
	    }
	    buf = calc[idx3];
	    calc[idx3] += carry;
	    if (calc[idx3] < buf) {
		carry_over = 1;
	    }
	    regs.ui64 = (uint64_t)src->cnt[idx1] * (uint64_t)dst->cnt[idx2];
	    carry = regs.ui32[1];
	    buf = calc[idx3];
	    calc[idx3] += regs.ui32[0];
	    if (calc[idx3] < buf) {
		carry_over = 1;
	    }
	}
    }
    for (idx1 = 0; idx1 < cnt_bufsiz; idx1++) {
	cnt[idx1] = calc[idx1];
    }
    delete src;
    delete dst;
    src = NULL;
    dst = NULL;
    return *this;
}

// ----------------------------------
/*
uintX_t&
uintX_t::operator *=(uintX_t& mul) {
    size_t sft = 0;
    uintX_t* tmp = new uintX_t(mul);
    uintX_t* calc = new uintX_t(*this);

    reset();
    while (sft < bitsiz) {
	if (tmp->cnt[0] & 1) {
	    *this += *calc << sft;
	}
	sft++;
	*tmp >>= 1;
    }
    delete calc;
    delete tmp;
    calc = NULL;
    tmp = NULL;
    return *this;
}
*/

// ----------------------------------
uintX_t&
uintX_t::operator *=(srcregs_t mul) {
    uintX_t* tmp = new uintX_t(mul, bitsiz);
    operator *=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}


// ----------------------------------
uintX_t&
uintX_t::operator *(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator *=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator *(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator *=(src);
}


// ----------------------------------
uintX_t&
uintX_t::operator /=(uintX_t& div) {
    size_t sftcnt = 0;
    size_t sft;
    uintX_t* tmp = new uintX_t(div);
    uintX_t* regs = new uintX_t(*this);
    uintX_t* calc = new uintX_t(0, bitsiz);

    if (div == *calc) {
	throw runtime_error("Zero Divied.");
    }
    reset();
    while (sftcnt < bitsiz) {
	sft = bitsiz - sftcnt - 1;
	*calc = *regs >> sft;
	if (*calc >= *tmp) {
	    BitSet(sft, 1);
	    *regs -= (*tmp << sft);
	}
	else {
	    BitSet(sft, 0);
	}
	sftcnt++;
    }
    delete calc;
    delete regs;
    delete tmp;
    calc = NULL;
    regs = NULL;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator /=(srcregs_t div) {
    uintX_t* tmp = new uintX_t(div, bitsiz);
    operator /=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator /(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator /=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator /(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator /=(src);
}


// ----------------------------------
uintX_t&
uintX_t::operator %=(uintX_t& div) {
    size_t sftcnt = 0;
    size_t sft;
    uintX_t* tmp = new uintX_t(div);
    uintX_t* regs = new uintX_t(*this);
    uintX_t* calc = new uintX_t(0, bitsiz);

    if (div == *calc) {
	throw runtime_error("Zero Divied.");
    }
    reset();
    while (sftcnt < bitsiz) {
	sft = bitsiz - sftcnt - 1;
	*calc = *regs;
	*calc >>= sft;
	if (*calc >= *tmp) {
	    //BitSet(sft, 1);
	    *calc = *tmp;
	    *calc <<= sft;
	    *regs -= *calc;
	}
	else {
	    //BitSet(sft, 0);
	}
	sftcnt++;
    }
    *this = *regs;
    delete calc;
    delete regs;
    delete tmp;
    calc = NULL;
    regs = NULL;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator %=(srcregs_t div) {
    uintX_t* tmp = new uintX_t(div, bitsiz);
    operator %=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator %(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator %=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator %(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator %=(src);
}


// bit operater.
// ----------------------------------
inline
uintX_t&
uintX_t::BitSet(size_t bitnum, int bit) {
    calcregs_t or_mask = 1;
    calcregs_t and_mask = 0 - 1;
    size_t sft = bitnum % calcbits;
    size_t idx = bitnum / calcbits;

    if (bitnum < bitsiz) {
	or_mask <<= sft;
	and_mask ^= or_mask;
	if (bit) {
	    cnt[idx] |= or_mask;
	}
	else {
	    cnt[idx] &= and_mask;
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator <<=(size_t sft) {
    size_t idx;
    size_t idx_src;
    size_t idx_dst;
    size_t diff;
    calcregs_t bits_forced_out;
    calcregs_t bits_register;

    if (sft >= bitsiz) {
	sft %= bitsiz;
    }
    if (sft == 0) {
	return *this;
    }
    if (sft >= calcbits) {
	diff = sft / calcbits;
	for (idx = 0; idx < cnt_bufsiz; ++idx) {
	    idx_dst = r_idx(idx);
	    idx_src = idx_dst - diff;
	    if (idx_src > idx_dst) {
		cnt[idx_dst] = 0;
	    }
	    else {
		cnt[idx_dst] = cnt[idx_src];
	    }
	}
	sft %= calcbits;
    }
    if (sft == 0) {
	return *this;
    }
    diff = calcbits - sft;
    bits_forced_out = 0;
    for (idx = 0; idx < cnt_bufsiz; ++idx) {
	bits_register = cnt[idx];
	cnt[idx] <<= sft;
	cnt[idx] |= bits_forced_out;
	bits_forced_out = bits_register >> diff;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator <<(size_t sft) {
    replace_tmp();
    return retv_tmp->operator <<=(sft);;
}

// ----------------------------------
uintX_t&
uintX_t::operator >>=(size_t sft) {
    size_t idx;
    size_t idx_dst;
    size_t idx_src;
    size_t diff;
    calcregs_t bits_forced_out;
    calcregs_t bits_register;

    if (sft >= bitsiz) {
	sft %= bitsiz;
    }
    if (sft == 0) {
	return *this;
    }
    if (sft >= calcbits) {
	diff = sft / calcbits;
	for (idx = 0; idx < cnt_bufsiz; ++idx) {
	    idx_src = idx + diff;
	    if (idx_src >= cnt_bufsiz) {
		cnt[idx] = 0;
	    }
	    else {
		cnt[idx] = cnt[idx_src];
	    }
	}
	sft %= calcbits;
    }
    if (sft == 0) {
	return *this;
    }
    diff = calcbits - sft;
    bits_forced_out = 0;
    for (idx = 0; idx < cnt_bufsiz; ++idx) {
	idx_dst = r_idx(idx);
	bits_register = cnt[idx_dst];
	cnt[idx_dst] >>= sft;
	cnt[idx_dst] |= bits_forced_out;
	bits_forced_out = bits_register << diff;
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator >>(size_t sft) {
    replace_tmp();
    return retv_tmp->operator >>=(sft);
}

// ----------------------------------
uintX_t&
uintX_t::operator |=(uintX_t& src) {
    size_t idx = 0;

    if (cnt_bufsiz > src.cnt_bufsiz) {
	while (idx < src.cnt_bufsiz) {
	    cnt[idx] |= src.cnt[idx];
	    idx++;
	}
    }
    else {
	while (idx < cnt_bufsiz) {
	    cnt[idx] |= src.cnt[idx];
	    idx++;
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator |=(srcregs_t src) {
    uintX_t* tmp = new uintX_t(src, bitsiz);
    operator |=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator |(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator |=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator |(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator |=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator &=(uintX_t& src) {
    size_t idx = 0;

    if (cnt_bufsiz > src.cnt_bufsiz) {
	while (idx < src.cnt_bufsiz) {
	    cnt[idx] &= src.cnt[idx];
	    idx++;
	}
	while (idx < cnt_bufsiz) {
	    cnt[idx] = 0;
	    idx++;
	}
    }
    else {
	while (idx < cnt_bufsiz) {
	    cnt[idx] &= src.cnt[idx];
	    idx++;
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator &=(srcregs_t src) {
    uintX_t* tmp = new uintX_t(src, bitsiz);
    operator &=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator &(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator &=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator &(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator &=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator ^=(uintX_t& src) {
    size_t idx = 0;

    if (cnt_bufsiz > src.cnt_bufsiz) {
	while (idx < src.cnt_bufsiz) {
	    cnt[idx] ^= src.cnt[idx];
	    idx++;
	}
	while (idx < cnt_bufsiz) {
	    cnt[idx] ^= 0;
	    idx++;
	}
    }
    else {
	while (idx < cnt_bufsiz) {
	    cnt[idx] ^= src.cnt[idx];
	    idx++;
	}
    }
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator ^=(srcregs_t src) {
    uintX_t* tmp = new uintX_t(src, bitsiz);
    operator ^=(*tmp);
    delete tmp;
    tmp = NULL;
    return *this;
}

// ----------------------------------
uintX_t&
uintX_t::operator ^(uintX_t& src) {
    replace_tmp();
    return retv_tmp->operator ^=(src);
}

// ----------------------------------
uintX_t&
uintX_t::operator ^(srcregs_t src) {
    replace_tmp();
    return retv_tmp->operator ^=(src);
}


// transfer for numeric string.
// ----------------------------------

// to hexadecimal strings.
// ----------------------------------
const char*
uintX_t::gethexdstr(STR_MODE mod) {
    size_t idx = 0;
    size_t idx_dst = 0;
    size_t idx_src = 0;
    size_t sft = 0;
    char* hex = NULL;
    char alpha_x = '\0';

    if (mod == NO_HEADER_SMALL_CAPS || mod == HEADER_SMALL_CAPS) {
	hex = "0123456789abcdef";
	alpha_x = 'x';
    }
    else if (mod == NO_HEADER_LERGE_CAPS || mod == HEADER_LERGE_CAPS) {
	hex = "0123456789ABCDEF";
	alpha_x = 'X';
    }
    if (mod == HEADER_SMALL_CAPS || mod == HEADER_LERGE_CAPS) {
	hexstr[0] = '0';
	hexstr[1] = alpha_x;
	idx_dst += 2;
    }
    for (idx = 0; idx < cnt_bufsiz; idx++) {
	idx_src = r_idx(idx);
	for (sft = calcbits - 4; sft < calcbits; sft -= 4) {
	    hexstr[idx_dst++] = hex[cnt[idx_src] >> sft & 0xf];
	    if (sft == 0 && idx_src != 0) {
		hexstr[idx_dst++] = '-';
	    }
	}
    }
    hexstr[idx_dst] = '\0';
    return hexstr;
}

// to binary strings.
// ----------------------------------
const char*
uintX_t::getbinstr() {
    size_t idx = 0;
    size_t idx_dst = 0;
    size_t idx_src = 0;
    size_t sft = 0;

    for (idx = 0; idx < cnt_bufsiz; idx++) {
	idx_src = r_idx(idx);
	sft = calcbits - 4;
	for (sft = calcbits - 1; sft < calcbits; sft--) {
	    binstr[idx_dst++] = '0' + (cnt[idx_src] >> sft & 1);
	    if (sft == 0 && idx_src != 0) {
		binstr[idx_dst++] = '-';
	    }
	}
    }
    binstr[idx_dst] = '\0';
    return binstr;
}

// to decimal strings.
// ----------------------------------
const char*
uintX_t::getdecstr(int sep_pos, const char sep_chr) {
    uintX_t zero(0, bitsiz);
    uintX_t ten(10, bitsiz);
    uintX_t calc(*this); 
    uintX_t copy(*this);
    size_t idx = 0;
    size_t cnt = 0;
    char* buf;
    char* tmp;

    while (copy != zero) {
	calc %= ten;
	decstr[idx++] = '0' + (char)calc.cnt[0];
	calc = copy /= ten;
	cnt++;
	if (sep_pos != 0) {
	    if ((cnt % sep_pos) == 0) {
		decstr[idx++] = sep_chr;
	    }
	}
    }
    if (idx == 0){
	decstr[idx++] = '0';
    }
    decstr[idx] = '\0';

    buf = new char[idx+1];
    for (cnt = 0; cnt < idx; cnt++) {
	buf[cnt] = decstr[idx-cnt-1];
    }
    buf[cnt] = '\0';
    if (buf[0] == sep_chr) {
	tmp = buf + 1;
	cnt--;
    }
    else {
	tmp = buf;
    }
    memcpy(decstr, tmp, cnt+1);
    delete buf;
    buf = NULL;
    tmp = NULL;
    return decstr;
}

// ----------------------------------
std::ostream&
operator <<(std::ostream& strm, uintX_t& src) {
    return strm << src.getdecstr();
}

// ----------------------------------
unsigned int
uintX_t::operator [](size_t idx) {

    if (idx >= 0 && idx < cnt_bufsiz) {
	return cnt[idx];
    }
    else {
	return 0;
    }
}

// ----------------------------------
size_t
uintX_t::bytesize() {

    return bitsiz >> 3;
}

// ----------------------------------
size_t
uintX_t::blocksize() {

    return cnt_bufsiz;
}

// ----------------------------------
size_t
uintX_t::regsbitsize() {

    return sizeof(calcregs_t) << 3;
}

