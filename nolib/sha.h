#ifndef SHA

#define SHA

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define w  32        // word   size in bits
#define ds 256       // digest size in bits
#define m  512       // block  size in bits

// algorithm functions
#define ROTL(x, n) ((x << n) | (x >> (w - n)))
#define ROTR(x, n) ((x >> n) | (x << (w - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

// check if machine is big-endian
#define ENDIAN (*(uint16_t *)"\0\xff" < 0x100)

// byteswap functions
#define BSWAP32(x) ((uint32_t)((((x) & 0x000000FF) << 24) | \
                                (((x) & 0x0000FF00) << 8)  | \
                                (((x) & 0x00FF0000) >> 8)  | \
                                (((x) & 0xFF000000) >> 24)))
#define BSWAP64(x) ((uint64_t)((((x) & 0x00000000000000FFULL) << 56) | \
                            	(((x) & 0x000000000000FF00ULL) << 40) | \
                            	(((x) & 0x0000000000FF0000ULL) << 24) | \
                            	(((x) & 0x00000000FF000000ULL) << 8)  | \
                            	(((x) & 0x000000FF00000000ULL) >> 8)  | \
                            	(((x) & 0x0000FF0000000000ULL) >> 24) | \
                            	(((x) & 0x00FF000000000000ULL) >> 40) | \
                            	(((x) & 0xFF00000000000000ULL) >> 56)))

// message block is block with 16 x 32 byte words = 512 bit
typedef uint32_t mblock[m/8];

// sha256 context
typedef struct {
    uint8_t *msg;
    mblock *mblocks;
    size_t size;
    size_t N;
    uint32_t debug;
    uint32_t H[8];
} sha256_ctx;

#ifdef __unix__
#define getline getline_f
#endif

// read line from standard input
int getline(uint8_t *s, uint32_t size);
// sha256 hash digest of msg
void sha256_hash(const char *msg, char *digest, int debug);
// print digest value
void digest_print(uint8_t *digest);

#endif