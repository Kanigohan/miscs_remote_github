/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha384.cc,v 1.2 2005/09/20 08:34:24 kani Exp $
 * $Date: 2005/09/20 08:34:24 $
 * $Revision: 1.2 $
 */

#include <sha384.hh>

// ---------------------------------
void
sha384::proc_init() {

    digest[0] = 0xcbbb9d5dc1059ed8ULL;
    digest[1] = 0x629a292a367cd507ULL;
    digest[2] = 0x9159015a3070dd17ULL;
    digest[3] = 0x152fecd8f70e5939ULL;
    digest[4] = 0x67332667ffc00b31ULL;
    digest[5] = 0x8eb44a8768581511ULL;
    digest[6] = 0xdb0c2e0d64f98fa7ULL;
    digest[7] = 0x47b5481dbefa4fa4ULL;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
sha384::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += digest_bytes / digest_size;
    }
}

// ---------------------------------
sha384::sha384() : sha512() {

    release_ptr(&block_buffer);
    release_ptr(&digest);
    release_ptr(&cnt);

    alg_name = "SHA384";
    max_message_bits = 128;

    digest_bits = 384;
    digest_bytes = digest_bits / 8;
    digest_size = digest_bytes / sizeof(uint64_t);
    digest_hexstr_bytes = (digest_bits / 4) + 1;
    digest_hexstr = new unsigned char[digest_hexstr_bytes];
    message_digest = new unsigned char[digest_bytes];

    block_bits = 1024;
    block_bytes = block_bits / 8;
    block_size = block_bytes / sizeof(uint64_t);
    
    block_buffer = new unsigned char[block_bytes];
    digest = new uint64_t[digest_size+2];
    cnt = new uintX_t(0, max_message_bits);

    proc_init();
}

// ---------------------------------
sha384::~sha384() {

    release_ptr(&block_buffer);
    release_ptr(&digest);
    release_ptr(&cnt);
}
