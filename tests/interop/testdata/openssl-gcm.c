/* Independent OpenSSL EVP AES-GCM oracle for bounded local test material.
 * No toolkit code is linked. Authentication completes before plaintext is written.
 */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define MAX_PLAINTEXT_BYTES 16384
#define GCM_NONCE_BYTES 12
#define GCM_TAG_BYTES 16
#define GCM_OVERHEAD_BYTES (GCM_NONCE_BYTES + GCM_TAG_BYTES)
static int read_file(const char *path, unsigned char *data, size_t max) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) return -1;
    size_t n = fread(data, 1, max, file);
    int failed = ferror(file) || fgetc(file) != EOF;
    if (fclose(file) != 0) failed = 1;
    return failed ? -1 : (int)n;
}
int main(int argc, char **argv) {
    unsigned char key[32], input[MAX_PLAINTEXT_BYTES + GCM_OVERHEAD_BYTES], output[MAX_PLAINTEXT_BYTES + GCM_OVERHEAD_BYTES], nonce[GCM_NONCE_BYTES];
    EVP_CIPHER_CTX *ctx = NULL;
    int result = 1, n = 0, final = 0;
    if (argc != 5 || (strcmp(argv[1], "encrypt") && strcmp(argv[1], "decrypt"))) return 2;
    int keysize = read_file(argv[2], key, sizeof(key));
    const EVP_CIPHER *cipher = keysize == 16 ? EVP_aes_128_gcm() : keysize == 24 ? EVP_aes_192_gcm() : keysize == 32 ? EVP_aes_256_gcm() : NULL;
    int size = read_file(argv[3], input, sizeof(input));
    if (cipher == NULL || size < 0 || (ctx = EVP_CIPHER_CTX_new()) == NULL) goto done;
    if (!strcmp(argv[1], "encrypt")) {
        if (size > MAX_PLAINTEXT_BYTES || RAND_bytes(nonce, sizeof(nonce)) != 1) goto done;
        memcpy(output, nonce, sizeof(nonce));
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, nonce) != 1 || EVP_EncryptUpdate(ctx, output + GCM_NONCE_BYTES, &n, input, size) != 1 || EVP_EncryptFinal_ex(ctx, output + GCM_NONCE_BYTES + n, &final) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, output + GCM_NONCE_BYTES + n + final) != 1) goto done;
        n += final + GCM_OVERHEAD_BYTES;
    } else {
        if (size < GCM_OVERHEAD_BYTES || EVP_DecryptInit_ex(ctx, cipher, NULL, key, input) != 1 || EVP_DecryptUpdate(ctx, output, &n, input + GCM_NONCE_BYTES, size - GCM_OVERHEAD_BYTES) != 1 || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES, input + size - GCM_TAG_BYTES) != 1 || EVP_DecryptFinal_ex(ctx, output + n, &final) != 1) goto done;
        n += final;
    }
    FILE *out = fopen(argv[4], "wb");
    if (out == NULL) goto done;
    int failed = fwrite(output, 1, (size_t)n, out) != (size_t)n;
    if (fclose(out) != 0) failed = 1;
    if (failed) goto done;
    result = 0;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(output, sizeof(output));
    return result;
}
