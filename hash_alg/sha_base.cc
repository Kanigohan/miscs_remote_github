/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha_base.cc,v 1.10 2005/09/22 07:38:24 kani Exp $
 * $Date: 2005/09/22 07:38:24 $
 * $Revision: 1.10 $
 */

#include <sha_base.hh>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

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

//-------------------
sha_base::sha_base() {
    alg_name = "";
    max_message_bits = 0;
    digest_bits = 0;
    digest_bytes = 0;
    digest_size = 0;
    digest_hexstr_bytes = 0;
    digest_hexstr = NULL;
    message_digest = NULL;
}

//-------------------
sha_base::~sha_base() {
    release_ptr(&digest_hexstr);
    release_ptr(&message_digest);
    release_ptr(&block_buffer);
    release_ptr(&cnt);
}

//------------------
const unsigned char*
sha_base::proc_2hexstr() {
    char* hexchar = "0123456789abcdef";
    unsigned char u8;
    size_t i, j;
    i = j = 0;
    while (i < digest_bytes) {
	u8 = message_digest[i++];
	digest_hexstr[j++] = hexchar[u8 >> 4 & 0xf];
	digest_hexstr[j++] = hexchar[u8 & 0xf];
    }
    digest_hexstr[j] = '\0';
    return digest_hexstr;
}

//-------------------
const unsigned char*
sha_base::proc_data(const char* str) {
    proc_init();
    proc_update((unsigned char*)str, strlen(str));
    proc_final();
    return proc_2hexstr();
}

//-------------------
const unsigned char*
sha_base::proc_file(const char* fname) {
    return proc_filechunk(fname, 0, 0);
}

//-------------------
const unsigned char*
sha_base::proc_filechunk(const char* fname, off_t begin, off_t length) {

    unsigned char buffer[READBLOCK];
    struct stat stbuf;
    int f, i, e;
    off_t n;

    proc_init();
    f = open((char*)fname, O_RDONLY);
    if (f < 0) {
	return 0;
    }
    if (fstat(f, &stbuf) < 0) {
	return 0;
    }
    if (begin > stbuf.st_size) {
	begin = stbuf.st_size;
    }
    if ((length == 0) || (length > stbuf.st_size - begin)) {
	length = stbuf.st_size - begin;
    }
    if (lseek(f, begin, SEEK_SET) < 0) {
	return 0;
    }
    n = length;
    i = 0;
    while (n > 0) {
	if (n > sizeof(buffer)) {
	    i = read(f, buffer, READBLOCK);
	}
	else {
	    i = read(f, buffer, n);
	}
	if (i < 0) { 
	    break;
	}
	proc_update(buffer, i);
	n -= i;
    } 
    e = errno;
    close(f);
    errno = e;
    if (i < 0) {
	return NULL;
    }
    proc_final();
    return proc_2hexstr();
}

//-------------------
const char*
sha_base::algorythm_name() {
    return alg_name;
}

//-------------------
const size_t
sha_base::digest_byte_length() {
    return digest_bits >> 2;
}

// ---------------------------------
void
sha_base::proc_update(unsigned char* src, size_t len) {

    size_t i;
    //uintX_t bitlen(len, max_message_bits);
    //bitlen <<= 3; // bytes*8 --> bits length
    //*cnt += bitlen;
    *cnt += len << 3;

    size_t remain_bytes = block_bytes - last_surplus_bytes;
    if (len >= remain_bytes) {
	memcpy(&block_buffer[last_surplus_bytes], src, remain_bytes);
	proc_hash(block_buffer);
	for (i = remain_bytes; i + block_bytes - 1 < len; i += block_bytes ) {
	    proc_hash(&src[i]);
	}
	last_surplus_bytes = 0;
    }
    else {
	i = 0;
    }
    memcpy(&block_buffer[last_surplus_bytes], &src[i], len - i);
    last_surplus_bytes = ((*cnt)[0] >> 3) & (block_bytes - 1);
}

// ---------------------------------
void
sha_base::proc_message_padding() {

    size_t cnt_bytes = cnt->bytesize();
    size_t cnt_blocks = cnt->blocksize();
    unsigned char* procbits = new unsigned char[cnt_bytes];
    
    size_t padd_bytes;
    size_t i, j;

    i = j = 0;
    j = cnt_bytes;
    while (i < cnt_blocks) {
	j -= cnt_bytes / cnt_blocks;
	block2bytes((*cnt)[i], &procbits[j]);
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
void
sha_base::proc_final() {

    proc_message_padding();
    proc_copy_digest();
}
