/*
 * Copyright(c) <2005>,<kani>
 * All rights reserved.
 *
 * The distribution of this text conforms to "New BSD license". 
 */

/*
 * $Id: main.cc,v 1.3 2005/09/26 15:11:15 kani Exp $
 * $Date: 2005/09/26 15:11:15 $
 * $Revision: 1.3 $
 */

/*
 * Brief : UNIX like "MD5" "SHA*" hashing process clone.
 */

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <time.h>
#include <err.h>
#include <sys/time.h>
#include <sys/resource.h>


#include <sha>
#include <md5.hh>

using namespace std;

// ------------------------------------------------------------------------
// -----------------------------------------------------------------------
const char* MDTestInput[] = {
    "", 
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    "MD5 has not yet (2001-09-03) been broken, but sufficient attacks have"
    " been made that its security is in some doubt",
    NULL
};

const char* MD5_TestOutput[] = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "0cc175b9c0f1b6a831c399e269772661",
    "900150983cd24fb0d6963f7d28e17f72",
    "f96b697d7cb7938d525a2f31aaf161d0",
    "c3fcd3d76192e4007dfb496cca67e13b",
    "d174ab98d277d9f5a5611c2c9f419d9f",
    "57edf4a22be3c955ac49da2e2107b67a",
    "b50663f41d44d92171cb9976bc118538",
    NULL
};

const char* SHA1_TestOutput[] = {
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "c12252ceda8be8994d5fa0290a47231c1d16aae3",
    "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
    "761c457bf73b14d27e9e9265c46f4b4dda11f940",
    "50abf5706a150990a08b2c5ea40fa0e585554732",
    "18eca4333979c4181199b7b4fab8786d16cf2846",
    NULL
};

const char* SHA224_TestOutput[] = {
    "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
    "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
    "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
    "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e",
    "5ae55f3779c8a1204210d7ed7689f661fbe140f96f272ab79e19d470",
    NULL
};

const char* SHA256_TestOutput[] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
    "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
    "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
    "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
    "e6eae09f10ad4122a0e2a4075761d185a272ebd9f5aa489e998ff2f09cbfdd9f",
    NULL
};

const char* SHA384_TestOutput[] = {
    "38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743"
    "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
    "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035d"
    "ce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
    "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "473ed35167ec1f5d8e550368a3db39be54639f828868e945"
    "4c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
    "feb67349df3db6f5924815d6c3dc133f091809213731fe5c"
    "7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
    "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa640"
    "39c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
    "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd"
    "9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
    "99428d401bf4abcd4ee0695248c9858b7503853acfae21a9"
    "cffa7855f46d1395ef38596fcd06d5a8c32d41a839cc5dfb",
    NULL
};

const char* SHA512_TestOutput[] = {
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
    "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53"
    "02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
    "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
    "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429"
    "955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
    "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c4"
    "5c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
    "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a"
    "2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
    "e8a835195e039708b13d9131e025f4441dbdc521ce625f245a436dcd762f54bf"
    "5cb298d96235e6c6a304e087ec8189b9512cbdf6427737ea82793460c367b9c3",
    NULL
};

// -----------------------------------------------------------------------
typedef
struct {
    char* const progname;
    sha_base* sha;
    const char** TestSuiteStr;
} alg_table;

alg_table algo[] = {
    {"md5", new md5, MD5_TestOutput},
    {"sha1", new sha1, SHA1_TestOutput},
    {"sha224", new sha224, SHA224_TestOutput},
    {"sha256", new sha256, SHA256_TestOutput},
    {"sha384", new sha384, SHA384_TestOutput},
    {"sha512", new sha512, SHA512_TestOutput}
};

// -----------------------------------------------------------------------
static int qflag = 0;
static int rflag = 0;
static int sflag = 0;

const int TEST_BLOCK_LEN = 10000;
const int TEST_BLOCK_COUNT = 100000;

// ------------------------------------------------------------------------
void
TestSuite(alg_table* alg) {
    int i;
    unsigned char* digest;
    for (i = 0; MDTestInput[i] != NULL; i++) {
	digest = (unsigned char*)alg->sha->proc_data(MDTestInput[i]);
	fprintf(stdout, "%s (\"%s\") = %s",
		alg->sha->algorythm_name(),
		MDTestInput[i],
		digest);
	if (strcmp((char*)digest, alg->TestSuiteStr[i]) != 0) {
	    fprintf(stdout, " - INCORRECT RESULT!\n");
	}
	else {
	    fprintf(stdout, " - verified correct\n");
	}
    }
}

// ------------------------------------------------------------------------
void
Filter(alg_table* alg, int tee) {
    size_t len;
    unsigned char buf[BUFSIZ];
    alg->sha->proc_init();
    while ((len = fread(buf, 1, BUFSIZ, stdin))) {
	if (tee && len != fwrite(buf, 1, len, stdout)) {
	    err(1, "stdout");
	}
	alg->sha->proc_update(buf, len);
    }
    alg->sha->proc_final();
    fprintf(stdout, "%s\n", alg->sha->proc_2hexstr());
}

// ------------------------------------------------------------------------
void
TimeTrial(alg_table* alg) {
    struct rusage before, after;
    struct timeval total;
    float seconds;
    unsigned char block[TEST_BLOCK_LEN];
    int i;

    fprintf(stdout,
	    "%s time trial. Digesting %d %d-byte blocks ...",
	    alg->sha->algorythm_name(),
	    TEST_BLOCK_COUNT,
	    TEST_BLOCK_LEN);
    fflush(stdout);

    for (i = 0; i < TEST_BLOCK_LEN; i++) {
	block[i] = (unsigned char)(i & 0xff);
    }
    getrusage(0, &before);

    for (i = 0; i < TEST_BLOCK_COUNT; i++) {
	alg->sha->proc_update(block, TEST_BLOCK_LEN);
    }
    alg->sha->proc_final();

    getrusage(0, &after);
    timersub(&after.ru_utime, &before.ru_utime, &total);
    seconds = total.tv_sec + (float) total.tv_usec / 1000000;
    fprintf(stdout, " done\n");
    fprintf(stdout, "Digest = %s", alg->sha->proc_2hexstr());
    fprintf(stdout, "\nTime = %f seconds\n", seconds);
    fprintf(stdout, "Speed = %f bytes/second\n",
	    (float) TEST_BLOCK_LEN * (float) TEST_BLOCK_COUNT / seconds);
}

// ------------------------------------------------------------------------
void
String(alg_table* alg, const char* str) {

    unsigned char* digest = (unsigned char*)alg->sha->proc_data(str);
    if (digest == NULL) {
	exit(1);
    }
    if (qflag) {
	fprintf(stdout, "%s\n", digest);
    }
    else if (rflag) {
	fprintf(stdout, "%s \"%s\"\n", digest, str);
    }
    else {
	fprintf(stdout, "%s (\"%s\") = %s\n",
		alg->sha->algorythm_name(),
		str,
		digest);
    }
}

// ------------------------------------------------------------------------
void
usage(alg_table* alg) {
    cerr << "usage: " << alg->progname << " [-pqrtx] [-s string] [files ...]" << endl;
}

// ------------------------------------------------------------------------
int
main(int argc, char** argv) {
    char* progname;
    unsigned char* digest;
    int idx;
    int opt;
    int fail = 0;

    progname = strrchr(argv[0], '/');
    if (progname == NULL) {
	progname = argv[0];
    }
    else {
	progname++;
    }
    for (idx = 0; idx < (sizeof(algo)/sizeof(alg_table)); idx++) {
	if (!strcasecmp(progname, algo[idx].progname)) {
	    break;
	}
    }
    if (idx >= (sizeof(algo)/sizeof(alg_table))) {
	idx = 0;
    }

    while ((opt = getopt(argc, argv, "pqrs:tx")) != -1) {
	switch(opt) {
	    case 'p':
		Filter(&algo[idx], 1);
		break;
	    case 'q':
		qflag = 1;
		break;
	    case 'r':
		rflag = 1;
		break;
	    case 's':
		sflag = 1;
		String(&algo[idx], optarg);
		break;
	    case 't':
		TimeTrial(&algo[idx]);
		break;
	    case 'x':
		TestSuite(&algo[idx]);
		break;
	    default:
		usage(&algo[idx]);
		return 1;
	}
    }
    argc -= optind;
    argv += optind;

    if (*argv) {
	while (*argv != NULL) {
	    if ((digest = (unsigned char*)algo[idx].sha->proc_file(*argv)) == NULL) {
		warn("%s", *argv);
		fail++;
	    }
	    else {
		if (qflag) {
		    fprintf(stdout, "%s\n", digest);
		}
		else if (rflag) {
		    fprintf(stdout, "%s %s\n", digest, *argv);
		}
		else {
		    fprintf(stdout, "%s (%s) = %s\n",
			    algo[idx].sha->algorythm_name(),
			    *argv,
			    digest);
		}
	    }
	    argv++;
	}
    }
    else if (!sflag && (optind == 1 || qflag || rflag)) {
	Filter(&algo[idx], 0);
    }

    if (fail) {
	return 1;
    }
    return 0;
}
