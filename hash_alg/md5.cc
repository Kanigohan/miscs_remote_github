/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: md5.cc,v 1.2 2005/09/22 03:41:10 kani Exp $
 * $Date: 2005/09/22 03:41:10 $
 * $Revision: 1.2 $
 */

#include <md5.hh>
#include <iostream>

using namespace std;

// ---------------------------------
const unsigned char
padd_patern[1024/8] = {
    0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

// ---------------------------------
const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// ---------------------------------
void
md5::proc_init() {

    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
md5::proc_hash(unsigned char* blockchunk) {

    uint32_t W[64];
    uint32_t h[4];
    size_t i, j;
    size_t a, b, c, d, x;
    int s1[4] = {7, 12, 17, 22};
    int s2[4] = {5, 9, 14, 20};
    int s3[4] = {4, 11, 16, 23};
    int s4[4] = {6, 10, 15, 21};

    //
    i = 0;
    j = 0;
    while (i < 16) {
	bytes2block(&blockchunk[j], W[i]);
	j += block_bytes / block_size;
	i++;
    }
    j = 1;
    while (i < 32) {
	W[i++] = W[j];
	j += 5;
	j %= 16;
    }
    j = 5;
    while (i < 48) {
	W[i++] = W[j];
	j += 3;
	j %= 16;
    }
    j = 0;
    while (i < 64) {
	W[i++] = W[j];
	j += 7;
	j %= 16;
    }

    a = 0;
    b = 1;
    c = 2;
    d = 3;
    for (i = 0; i < 4; i++) {
	h[i] = digest[i];
    }

    for (i = 0; i < 64; i++) {	
	if (i >= 0 && i < 16) {
	    h[a] = h[b] + ROTL(h[a] + F(h[b], h[c], h[d]) + W[i] + K[i], s1[i%4]);
	}
	if (i >= 16 && i < 32) {	
	    h[a] = h[b] + ROTL(h[a] + G(h[b], h[c], h[d]) + W[i] + K[i], s2[i%4]);
	}
	if (i >= 32 && i < 48) {
	    h[a] = h[b] + ROTL(h[a] + H(h[b], h[c], h[d]) + W[i] + K[i], s3[i%4]);
	}
	if (i >= 48 && i < 64) {
	    h[a] = h[b] + ROTL(h[a] + I(h[b], h[c], h[d]) + W[i] + K[i], s4[i%4]);
	}
	x = d;
	d = c;
	c = b;
	b = a;
	a = x;
    }
    for (i = 0; i < 4; i++) {
	digest[i] += h[i];
    }
}

// ---------------------------------
void
md5::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += digest_bytes / digest_size;
    }
}

// ---------------------------------
void
md5::proc_message_padding() {

    size_t cnt_bytes = cnt->bytesize();
    size_t cnt_blocks = cnt->blocksize();
    unsigned char* procbits = new unsigned char[cnt_bytes];
    //uint32_t u;

    size_t padd_bytes;
    size_t i, j;

    i = j = 0;
    j = 0;
    while (i < cnt_blocks) {
	block2bytes((*cnt)[i], &procbits[j]);
	j += cnt_bytes / cnt_blocks;
	i++;
    }

    if (last_surplus_bytes < (block_bytes - cnt_bytes)) {
	padd_bytes = (block_bytes - cnt_bytes) - last_surplus_bytes;
    }
    else {
	padd_bytes = ((block_bytes << 1) - cnt_bytes) - last_surplus_bytes;
    }
    proc_update((unsigned char*)padd_patern, padd_bytes);
    proc_update(procbits, cnt_bytes);
    release_ptr(&procbits);
}

// ---------------------------------
md5::md5() : sha_base() {

    alg_name = "MD5";
    max_message_bits = 64;

    digest_bits = 128;
    digest_bytes = digest_bits / 8;
    digest_size = digest_bytes / sizeof(uint32_t);
    digest_hexstr_bytes = (digest_bits / 4) + 1;
    digest_hexstr = new unsigned char[digest_hexstr_bytes];
    message_digest = new unsigned char[digest_bytes];

    block_bits = 512;
    block_bytes = block_bits / 8;
    block_size = block_bytes / sizeof(uint32_t);
    
    block_buffer = new unsigned char[block_bytes];
    digest = new uint32_t[digest_size];
    cnt = new uintX_t(0, max_message_bits);

    proc_init();
}

// ---------------------------------
md5::~md5() {

    release_ptr(&digest);
}
