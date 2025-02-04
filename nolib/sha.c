#include "sha.h"

// algorithm constants
const uint32_t K[] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

// initial hash values
const uint32_t H0[] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
};

// read line from standard input
int getline(uint8_t *s, uint32_t size) {
    fgets(s, size, stdin);
    *strchr(s, '\n') = 0;
    return (int) strlen(s);
}

// message padding
void sha256_padding(sha256_ctx *ctx) {
    uint64_t l = strlen(ctx->msg) * 8;
    uint32_t k = (l % 448) ? 448 - (l % 448) : m;
    uint64_t ls = ENDIAN ? l : BSWAP64(l);
    ctx->size = (l + k + 64) / 8;
    uint8_t *buf = calloc(ctx->size, sizeof(uint8_t));
    strcpy(buf, ctx->msg);
    buf[l / 8] = 1 << (8 - 1);
    memcpy(&buf[ctx->size-8], &ls, sizeof(uint64_t));
    ctx->msg = buf;
}

// parse message into message blocks
void sha256_parse(sha256_ctx *ctx) {
    ctx->N = ctx->size * 8 / m;
    ctx->mblocks = malloc(ctx->N * 16 * sizeof(uint32_t));
    uint32_t *wrdptr = (uint32_t *) ctx->msg;
    for (int i = 0; i < ctx->N; i++) {
        for (int j = 0; j < 16; j++) {
            uint32_t n = wrdptr[i * 16 + j];
            ctx->mblocks[i][j] = ENDIAN ? n : BSWAP32(n);
        }
    }
}

// print hash values
void sha256_hash_print(sha256_ctx *ctx) {
    for (int i = 0; i < 8; i++) {
        printf("H[%d] = %08X\n", i, ctx->H[i]);
    }
    putchar('\n');
}

// print block values
void sha256_block_print(sha256_ctx *ctx, int i) {
    puts("Block contents:");
    for (int j = 0; j < 16; j++) {
        printf("W[%d] = %08X\n", j, ctx->mblocks[i][j]);
    }
    putchar('\n');
}

// print variables
void sha256_vars_print(uint32_t *vars) {
    for (int i = 0; i < 8; i++) {
        printf("%08X ", vars[i]);
    }
    putchar('\n');
}

// initialize context
void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->H, H0, 8 * sizeof(uint32_t));
    if (ctx->debug) {
        putchar('\n');
        puts("Initial hash value:");
        sha256_hash_print(ctx);
    }
}

// update context
void sha256_update(sha256_ctx *ctx, uint8_t *msg) {
    uint32_t W[64] = {0};
    uint32_t a, b, c, d, e, f, g, h, T1, T2;
    ctx->msg = msg;
    sha256_padding(ctx);
    sha256_parse(ctx);
    for (int i = 0; i < ctx->N; i++) {
        for (int t = 0; t < 16; t++) {
            W[t] = ctx->mblocks[i][t];
        }
        if (ctx->debug) {
            sha256_block_print(ctx, i);
        }
        for (int t = 16; t < 64; t++) {
            W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16];
        }
        a = ctx->H[0];
        b = ctx->H[1];
        c = ctx->H[2];
        d = ctx->H[3];
        e = ctx->H[4];
        f = ctx->H[5];
        g = ctx->H[6];
        h = ctx->H[7];
        if (ctx->debug) {
            printf("  ");
            for (int i = 0; i < 8; i++) {
                printf("%9c", 'A' + i);
            }
            putchar('\n');
        }
        for (int t = 0; t < 64; t++) {
            T1 = h + S1(e) + CH(e, f, g) + K[t] + W[t];
            T2 = S0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
            if (ctx->debug) {
                uint32_t vars[] = {a, b, c, d, e, f, g, h};
                printf("t=%2d: ", t);
                sha256_vars_print(vars);
            }
        }
        ctx->H[0] += a;
        ctx->H[1] += b;
        ctx->H[2] += c;
        ctx->H[3] += d;
        ctx->H[4] += e;
        ctx->H[5] += f;
        ctx->H[6] += g;
        ctx->H[7] += h;
        if (ctx->debug) {
            putchar('\n');
            sha256_hash_print(ctx);
        }
    }
}

// copy hash value into digest buffer
void sha256_final(sha256_ctx *ctx, uint8_t *digest) {
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 4; j++) {
            uint32_t n = ENDIAN ? ctx->H[i] : BSWAP32(ctx->H[i]);
            memcpy(digest + i * 4, &n, sizeof(uint32_t));
        }
    }
}

// free data from context
void sha256_free(sha256_ctx *ctx) {
    free(ctx->msg);
    free(ctx->mblocks);
}

// print digest value
void digest_print(uint8_t *digest) {
    printf("Digest: ");
    for (int i = 0; i < ds / 8; i++) {
        if (i > 0 && i % 4 == 0) {
            putchar(' ');
        }
        printf("%02X", digest[i]);
    }
    putchar('\n');
}

// sha256 hash digest of msg
void sha256_hash(const char *msg, char *digest, int debug) {
    sha256_ctx ctx = {0};
    ctx.debug = debug;
    sha256_init(&ctx);
    sha256_update(&ctx, msg);
    sha256_final(&ctx, digest);
    sha256_free(&ctx);
}