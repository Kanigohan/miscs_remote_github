/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 *  The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: sha512.cc,v 1.15 2005/09/23 15:41:55 kani Exp $
 * $Date: 2005/09/23 15:41:55 $
 * $Revision: 1.15 $
 */

#include <sha512.hh>

// ---------------------------------
const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

// ---------------------------------
void
sha512::proc_init() {

    digest[0] = 0x6a09e667f3bcc908ULL;
    digest[1] = 0xbb67ae8584caa73bULL;
    digest[2] = 0x3c6ef372fe94f82bULL;
    digest[3] = 0xa54ff53a5f1d36f1ULL;
    digest[4] = 0x510e527fade682d1ULL;
    digest[5] = 0x9b05688c2b3e6c1fULL;
    digest[6] = 0x1f83d9abfb41bd6bULL;
    digest[7] = 0x5be0cd19137e2179ULL;

    last_surplus_bytes = 0;
    block_clear(digest_hexstr, digest_hexstr_bytes);
    block_clear(message_digest, digest_bytes);
    block_clear(block_buffer, block_bytes);
    cnt->reset();
}

// ---------------------------------
void
sha512::proc_hash(unsigned char* blockchunk) {

    uint64_t W[80];
    uint64_t H[8];
    uint64_t T1, T2;
    enum idx{a, b, c, d, e, f, g, h};
    size_t i, j, k;

    //
    k = block_bytes / block_size;
    j = 0;
    for (i = 0; i < block_size; i++) {
	bytes2block(&blockchunk[j], W[i]);
	j += sizeof(uint64_t);
    }
    for (i = block_size; i < 80; i++) {
	W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }

    H[a] = digest[a];
    H[b] = digest[b];
    H[c] = digest[c];
    H[d] = digest[d];
    H[e] = digest[e];
    H[f] = digest[f];
    H[g] = digest[g];
    H[h] = digest[h];

/*
  for (i = 0; i < 80; i++) {
  T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + K[i] + W[i];
  T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
  H[h] = H[g];
  H[g] = H[f];
  H[f] = H[e];
  H[e] = H[d] + T1;
  H[d] = H[c];
  H[c] = H[b];
  H[b] = H[a];
  H[a] = T1 + T2;

  printf("T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x%016llxULL;\n", K[i]);
  printf("T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);\n");
  printf("H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;\n");
  printf("H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;\n\n");

  }
*/
    i = 0;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x428a2f98d728ae22ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x7137449123ef65cdULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xb5c0fbcfec4d3b2fULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xe9b5dba58189dbbcULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x3956c25bf348b538ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x59f111f1b605d019ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x923f82a4af194f9bULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xab1c5ed5da6d8118ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd807aa98a3030242ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x12835b0145706fbeULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x243185be4ee4b28cULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x550c7dc3d5ffb4e2ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x72be5d74f27b896fULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x80deb1fe3b1696b1ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x9bdc06a725c71235ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc19bf174cf692694ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xe49b69c19ef14ad2ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xefbe4786384f25e3ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x0fc19dc68b8cd5b5ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x240ca1cc77ac9c65ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2de92c6f592b0275ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4a7484aa6ea6e483ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x5cb0a9dcbd41fbd4ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x76f988da831153b5ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x983e5152ee66dfabULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa831c66d2db43210ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xb00327c898fb213fULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xbf597fc7beef0ee4ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc6e00bf33da88fc2ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd5a79147930aa725ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x06ca6351e003826fULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x142929670a0e6e70ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x27b70a8546d22ffcULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2e1b21385c26c926ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4d2c6dfc5ac42aedULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x53380d139d95b3dfULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x650a73548baf63deULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x766a0abb3c77b2a8ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x81c2c92e47edaee6ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x92722c851482353bULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa2bfe8a14cf10364ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa81a664bbc423001ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc24b8b70d0f89791ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc76c51a30654be30ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd192e819d6ef5218ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd69906245565a910ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xf40e35855771202aULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x106aa07032bbd1b8ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x19a4c116b8d2d0c8ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x1e376c085141ab53ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x2748774cdf8eeb99ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x34b0bcb5e19b48a8ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x391c0cb3c5c95a63ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4ed8aa4ae3418acbULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x5b9cca4f7763e373ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x682e6ff3d6b2b8a3ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x748f82ee5defb2fcULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x78a5636f43172f60ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x84c87814a1f0ab72ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x8cc702081a6439ecULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x90befffa23631e28ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xa4506cebde82bde9ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xbef9a3f7b2c67915ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xc67178f2e372532bULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xca273eceea26619cULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xd186b8c721c0c207ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xeada7dd6cde0eb1eULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0xf57d4f7fee6ed178ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x06f067aa72176fbaULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x0a637dc5a2c898a6ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x113f9804bef90daeULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x1b710b35131c471bULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x28db77f523047d84ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x32caab7b40c72493ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x3c9ebe0a15c9bebcULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x431d67c49c100d4cULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x4cc5d4becb3e42b6ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x597f299cfc657e2aULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x5fcb6fab3ad6faecULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    T1 = H[h] + SIGMA1(H[e]) + Ch(H[e], H[f], H[g]) + W[i++] + 0x6c44198c4a475817ULL;
    T2 = SIGMA0(H[a]) + Maj(H[a], H[b], H[c]);
    H[h] = H[g]; H[g] = H[f]; H[f] = H[e]; H[e] = H[d] + T1;
    H[d] = H[c]; H[c] = H[b]; H[b] = H[a]; H[a] = T1 + T2;

    digest[a] += H[a];
    digest[b] += H[b];
    digest[c] += H[c];
    digest[d] += H[d];
    digest[e] += H[e];
    digest[f] += H[f];
    digest[g] += H[g];
    digest[h] += H[h];
}

// ---------------------------------
void
sha512::proc_copy_digest() {

    size_t i, j;
    i = j = 0;
    while (i < digest_size) {
	block2bytes(digest[i++], &message_digest[j]);
	j += sizeof(uint64_t);
    }
}

// ---------------------------------
sha512::sha512() : sha_base() {

    alg_name = "SHA512";
    max_message_bits = 128;

    digest_bits = 512;
    digest_bytes = digest_bits / 8;
    digest_size = digest_bytes / sizeof(uint64_t);
    digest_hexstr_bytes = (digest_bits / 4) + 1;
    digest_hexstr = new unsigned char[digest_hexstr_bytes];
    message_digest = new unsigned char[digest_bytes];

    block_bits = 1024;
    block_bytes = block_bits / 8;
    block_size = block_bytes / sizeof(uint64_t);
    
    block_buffer = new unsigned char[block_bytes];
    digest = new uint64_t[digest_size];
    cnt = new uintX_t(0, max_message_bits);

    proc_init();
}

// ---------------------------------
sha512::~sha512() {

    release_ptr(&digest);
}
