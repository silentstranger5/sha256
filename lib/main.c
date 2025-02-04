#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(void) {
    EVP_MD_CTX *ctx = NULL;
    EVP_MD *sha256 = NULL;
    unsigned char msg[512];
    unsigned int len = 0;
    unsigned char *digest = NULL;
    int ret = 1;

    printf("Input message: ");
    fgets(msg, 512, stdin);
    *strchr(msg, '\n') = 0;

    /* Create a context for the digest operation */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        goto err;

    /* Fetch the SHA256 algorithm implementation for doing the digest */
    sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (sha256 == NULL)
        goto err;

    /* Initialize the digest operation */
    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
        goto err;

    /* Pass the message to be digested */
    if (!EVP_DigestUpdate(ctx, msg, strlen(msg)))
        goto err;

    /* Allocate the output buffer */
    digest = OPENSSL_malloc(EVP_MD_get_size(sha256));
    if (digest == NULL)
        goto err;

    /* Now calculate the digest itself */
    if (!EVP_DigestFinal_ex(ctx, digest, &len))
        goto err;

    /* Print out the digest result */
    BIO_dump_fp(stdout, digest, len);

    ret = 0;

err:
    /* Clean up all the resources we allocated */
    OPENSSL_free(digest);
    EVP_MD_free(sha256);
    EVP_MD_CTX_free(ctx);
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    return ret;
}
