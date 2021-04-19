/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha1.cc,v 1.3 2005/09/21 00:36:31 kani Exp $
 * $Date: 2005/09/21 00:36:31 $
 * $Revision: 1.3 $
 */

#include <sha1.hh>

// ---------------------------------
void
sha1::proc_init() {

    digest[0] = 0x67452301;
    digest[1] = 0xefcdab89;
    digest[2] = 0x98badcfe;
    digest[3] = 0x10325476;
    digest[4] = 0xc3d2e1f0;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
sha1::proc_hash(unsigned char* blockchunk) {

    uint32_t W[80];
    uint32_t H[5];
    uint32_t T = 0;
    enum idx{a, b, c, d, e};
    size_t i, j;

    //
    j = 0;
    for (i = 0; i < block_size; i++) {
	bytes2block(&blockchunk[j], W[i]);
	j += block_bytes / block_size;
    }
    for (i = block_size; i < 80; i++) {
	W[i] = ROTL(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1);
    }
    for (i = 0; i < 5; i++) {
	H[i] = digest[i];
    }

    for (i = 0; i < 80; i++) {
	if (i >= 0 && i < 20) {
	    T = ROTL(H[a], 5) + Ch(H[b], H[c], H[d]) + H[e] + 0x5a827999 + W[i];
	}
	if (i >= 20 && i < 40) {
	    T = ROTL(H[a], 5) + Parity(H[b], H[c], H[d]) + H[e] + 0x6ed9eba1 + W[i];
	}
	if (i >= 40 && i < 60) {
	    T = ROTL(H[a], 5) + Maj(H[b], H[c], H[d]) + H[e] + 0x8f1bbcdc + W[i];
	}
	if (i >= 60 && i < 80) {
	    T = ROTL(H[a], 5) + Parity(H[b], H[c], H[d]) + H[e] + 0xca62c1d6 + W[i];
	}
	H[e] = H[d];
	H[d] = H[c];
	H[c] = ROTL(H[b], 30);
	H[b] = H[a];
	H[a] = T;
    }

    for (i = 0; i < 5; i++) {
	digest[i] += H[i];
    }
}

// ---------------------------------
void
sha1::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += digest_bytes / digest_size;
    }
}

// ---------------------------------
sha1::sha1() : sha_base() {

    alg_name = "SHA1";
    max_message_bits = 64;

    digest_bits = 160;
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
sha1::~sha1() {

    release_ptr(&digest);
}
