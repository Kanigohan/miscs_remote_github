#include <sha>
#include <md5.hh>

using namespace std;

typedef
struct {
    const char* progname;
    sha_base* sha;
} alg_table;

alg_table alg[] = {
    {"md5", new md5},
    {"sha1", new sha1},
    {"sha224", new sha224},
    {"sha256", new sha256},
    {"sha384", new sha384},
    {"sha512", new sha512}
};

int
main(int argc, char** argv) {
    const char* progname;
    size_t idx;

    if (argc <= 1) {
	cout << "usage: sha[1, 224, 256, 384, 512] filename" << endl;
	return -1;
    }

    if ((progname = strrchr(argv[0], '/')) == NULL) {
	progname = argv[0];
    }
    else {
	progname++;
    }

    for (idx = 0; idx < sizeof(alg)/sizeof(*alg); idx++) {
	if (strcasecmp(alg[idx].progname, progname) == 0) {
	    break;
	}
    }

    if (idx == sizeof(alg)/sizeof(*alg)) {
	idx = 0;
    }

    cout << alg[idx].sha->algorythm_name();
    cout << " (" << argv[1] << ") = ";
    cout << alg[idx].sha->proc_file(argv[1]);
    cout << endl;
/*
    cout << alg[idx].sha->algorythm_name();
    cout << " (abc) = ";
    cout << alg[idx].sha->proc_data("abc");
    cout << endl;
*/
    return 0;
}
