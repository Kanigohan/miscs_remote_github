/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha224.cc,v 1.2 2005/09/20 08:34:24 kani Exp $
 * $Date: 2005/09/20 08:34:24 $
 * $Revision: 1.2 $
 */

#include <sha224.hh>

// ---------------------------------
void
sha224::proc_init() {

    digest[0] = 0xc1059ed8;
    digest[1] = 0x367cd507;
    digest[2] = 0x3070dd17;
    digest[3] = 0xf70e5939;
    digest[4] = 0xffc00b31;
    digest[5] = 0x68581511;
    digest[6] = 0x64f98fa7;
    digest[7] = 0xbefa4fa4;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
sha224::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += digest_bytes / digest_size;
    }
}

// ---------------------------------
sha224::sha224() : sha256() {

    release_ptr(&block_buffer);
    release_ptr(&digest);
    release_ptr(&cnt);

    alg_name = "SHA224";
    max_message_bits = 64;

    digest_bits = 224;
    digest_bytes = digest_bits / 8;
    digest_size = digest_bytes / sizeof(uint32_t);
    digest_hexstr_bytes = (digest_bits / 4) + 1;
    digest_hexstr = new unsigned char[digest_hexstr_bytes];
    message_digest = new unsigned char[digest_bytes];

    block_bits = 512;
    block_bytes = block_bits / 8;
    block_size = block_bytes / sizeof(uint32_t);
    
    block_buffer = new unsigned char[block_bytes];
    digest = new uint32_t[digest_size+1];
    cnt = new uintX_t(0, max_message_bits);

    proc_init();
}

// ---------------------------------
sha224::~sha224() {

    release_ptr(&block_buffer);
    release_ptr(&digest);
    release_ptr(&cnt);
}
