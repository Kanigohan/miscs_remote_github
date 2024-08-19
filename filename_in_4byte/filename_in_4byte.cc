#include <iostream>
#include <string>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

using namespace std;

bool is4bytes(unsigned char c) {
    return (bool)((c & 0xf8) == 0xf0);
}

//
bool chk_fnam_4bytes(string &fname) {

    string::iterator it;
    for (it = fname.begin(); it != fname.end(); it++) {
	if (is4bytes(*it)) {
	    return true;
	}
    }
    return false;
}

//
int main(int argc, char** argv) {

    string fname;
    ifstream* ifs;
    int retc = 0;
    
    ios_base::sync_with_stdio();
    if (!isatty(fileno(stdin))) {
        ifs = (ifstream*)&cin; // it was called by the pipe connection.
    }

    while (1) {
	if (ifs->eof()) {
	    break;
	}
	getline(*ifs, fname);
	if (chk_fnam_4bytes(fname)) {
	    cout << "found 4bytes charactor in " << fname << endl;
	    retc = 1;
	}
    }
    return retc;
}

//
#include <iostream>
#include <string>
#include <vector>

// UTF-8のバイト列の中で4バイト文字が始まる位置を調べる関数
std::vector<size_t> findFourByteCharacters(const std::string& str) {
    std::vector<size_t> positions;
    size_t i = 0;
    while (i < str.size()) {
        unsigned char c = static_cast<unsigned char>(str[i]);
        if ((c & 0xF8) == 0xF0) {
            // 4バイト文字の先頭バイトを発見
            positions.push_back(i);
            i += 4; // 4バイト文字をスキップ
        } else if ((c & 0xE0) == 0xC0) {
            i += 2; // 2バイト文字をスキップ
        } else if ((c & 0xF0) == 0xE0) {
            i += 3; // 3バイト文字をスキップ
        } else {
            i += 1; // 1バイト文字をスキップ
        }
    }
    return positions;
}

int main() {
    // テストするファイル名（UTF-8エンコード）
    std::string filename;
    std::cout << "ファイル名を入力してください: ";
    std::getline(std::cin, filename);
    
    // 4バイト文字の位置を取得
    std::vector<size_t> positions = findFourByteCharacters(filename);
    
    // 結果を表示
    if (!positions.empty()) {
        std::cout << "4バイト文字は以下の位置に含まれています:" << std::endl;
        for (size_t pos : positions) {
            std::cout << pos << "バイト目" << std::endl;
        }
    } else {
        std::cout << "4バイト文字は含まれていません。" << std::endl;
    }
    
    return 0;
}
