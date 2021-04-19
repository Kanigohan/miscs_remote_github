/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha256.cc,v 1.4 2005/09/23 15:41:55 kani Exp $
 * $Date: 2005/09/23 15:41:55 $
 * $Revision: 1.4 $
 */

#include <sha256.hh>

// ---------------------------------
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ---------------------------------
void
sha256::proc_init() {

    digest[0] = 0x6a09e667;
    digest[1] = 0xbb67ae85;
    digest[2] = 0x3c6ef372;
    digest[3] = 0xa54ff53a;
    digest[4] = 0x510e527f;
    digest[5] = 0x9b05688c;
    digest[6] = 0x1f83d9ab;
    digest[7] = 0x5be0cd19;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
sha256::proc_hash(unsigned char* blockchunk) {

    uint32_t W[64];
    uint32_t H[8];
    uint32_t T1, T2;
    enum idx{a, b, c, d, e, f, g, h};
    size_t i, j, k;

    //
    k = block_bytes / block_size;
    j = 0;
    for (i = 0; i < block_size; i++) {
	bytes2block(&blockchunk[j], W[i]);
	j += sizeof(uint32_t);
    }
    while(i < 64) {
	W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
	i++;
    }

    H[0] = digest[0];
    H[1] = digest[1];
    H[2] = digest[2];
    H[3] = digest[3];
    H[4] = digest[4];
    H[5] = digest[5];
    H[6] = digest[6];
    H[7] = digest[7];

/*
  for (i = 0; i < 64; i++) {
  T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i] +  K[i];
  T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
  H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
  H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

  printf("T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x%08x;\n", K[i]);
  cout << "T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);" << endl;
  cout << "H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;" << endl;
  cout << "H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;" << endl << endl;
  }
*/
    i = 0;
    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x428a2f98;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x71374491;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xb5c0fbcf;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xe9b5dba5;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x3956c25b;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x59f111f1;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x923f82a4;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xab1c5ed5;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd807aa98;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x12835b01;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x243185be;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x550c7dc3;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x72be5d74;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x80deb1fe;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x9bdc06a7;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc19bf174;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xe49b69c1;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xefbe4786;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x0fc19dc6;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x240ca1cc;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2de92c6f;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4a7484aa;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x5cb0a9dc;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x76f988da;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x983e5152;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa831c66d;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xb00327c8;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xbf597fc7;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc6e00bf3;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd5a79147;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x06ca6351;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x14292967;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x27b70a85;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2e1b2138;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4d2c6dfc;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x53380d13;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x650a7354;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x766a0abb;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x81c2c92e;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x92722c85;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa2bfe8a1;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa81a664b;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc24b8b70;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc76c51a3;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd192e819;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd6990624;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xf40e3585;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x106aa070;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x19a4c116;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x1e376c08;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2748774c;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x34b0bcb5;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x391c0cb3;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4ed8aa4a;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x5b9cca4f;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x682e6ff3;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x748f82ee;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x78a5636f;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x84c87814;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x8cc70208;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x90befffa;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa4506ceb;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xbef9a3f7;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc67178f2;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    digest[0] += H[0];
    digest[1] += H[1];
    digest[2] += H[2];
    digest[3] += H[3];
    digest[4] += H[4];
    digest[5] += H[5];
    digest[6] += H[6];
    digest[7] += H[7];
}

// ---------------------------------
void
sha256::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += sizeof(uint32_t);
    }
}

// ---------------------------------
sha256::sha256() : sha_base() {

    alg_name = "SHA256";
    max_message_bits = 64;

    digest_bits = 256;
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
sha256::~sha256() {

    release_ptr(&digest);
}
