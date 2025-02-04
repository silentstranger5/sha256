#include "sha.h"

// digest size
#define DSIZE 32
// message size
#define MSIZE 512

int main(int argc, char **argv) {
    uint8_t msg[MSIZE];
    uint8_t digest[DSIZE];
    uint32_t debug = (argc == 2 && !strcmp(argv[1], "-d"));
    printf("Input Message: ");
    getline(msg, MSIZE);
    sha256_hash(msg, digest, debug);
    digest_print(digest);
    return 0;
}