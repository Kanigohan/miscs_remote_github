/*
 * $Id: trans_newline.cc 1 2012-03-07 09:04:17Z kani $
 * $Author: kani $
 * $Revision: 1 $
 * $Date: 2012-03-07 18:04:17 +0900 (水, 07  3月 2012) $
 */

/*
 * 本ソースコードのファイルを2条項BSDライセンスに従い使用されることを宣言する。
 */

/*
 * Copyright 2012 Isao Kawashima(kani@diana.dti.ne.jp,
 *                               pp-kani@po1.dti2.ne.jp). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sys/capsicum.h>

using namespace std;

const char* new_line[3] = {
    "\r\n", // for DOS/Windows
    "\n",   // for Unix
    "\r"    // for Macintosh
};

/*
 * 改行コードの変換
 */
int 
main(int argc, char** argv) {

    int optflags;
    ifstream* ifs;
    int code_selector = 1;
    char read_c;

    while ((optflags = getopt(argc, argv, "dwum")) != -1) {
	switch (optflags) {
	    case 'd': // DOS/Windows new line 0x0d 0x0f(CR+LF)
	    case 'w': // DOS/Windows new line 0x0d 0x0f(CR+LF)
		code_selector = 0;
		break;
	    case 'u': // Unix new line 0x0f(LF) (default)
		code_selector = 1;
		break;
	    case 'm': // Macintosh new line 0x0d(CR)
		code_selector = 2;
		break;
	    default:
		cerr << "Usage: trans_newline -[dum] file_name" << endl;
		cerr << "Options" << endl;
		cerr << "-d: trans DOS/Windows newline code (CR+LF)" << endl;
		cerr << "-u: trans Unix        newline code (LF)" << endl;
		cerr << "-m: trans Macintosh   newline code (CR)" << endl;
		exit(0);
	}
    }
    argc -= optind;
    argv += optind;

/*
 * pipeで継がれた起動であれば、cinをifstreamに割り当て
 * 然もなくば、指定されたファイルをbinary-modeで開きifstreamに割り当て
 */
    ios_base::sync_with_stdio();
    if (!isatty(fileno(stdin))) {
	ifs = (ifstream*)&cin; // it was called by the pipe connection.
    }
    else {
	ifs = new(ifstream);
	ifs->open(*argv, ios::in|ios::binary);
	if (!ifs->is_open()) {
	    cerr << "Open file failed. " << argv[1] << endl;
	    return -1;
	}
    }

    int capability = cap_enter(); {
	if (capability != 0) {
	    cerr << "Youe system is bot support \"Capability\"" << endl;
	}

	while (1) {
	    ifs->read(&read_c, sizeof(char));
	    if (ifs->eof()) {
		break;
	    }
	    switch (read_c) {
		case '\r':
		    ifs->read(&read_c, sizeof(char)); // CRの後にLFが無いか読んでみる
		    // LFじゃ無かったらCR-onlyの改行とみなす
		    if (read_c != '\n') {
			cout << new_line[code_selector] << flush;
		    }
		    ifs->unget(); // 先のreadを読まなかった事にする
		    break;
		case '\n':
		    cout << new_line[code_selector] << flush;
		    break;
		default:
		    cout << read_c;
	    }
	}
	ifs->close();
    } // exit capability mode
    return 0;
}
