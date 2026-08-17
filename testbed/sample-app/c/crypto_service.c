/* Testbed C crypto usage: OpenSSL EVP + legacy APIs + libsodium */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <sodium.h>

void hash_legacy(const unsigned char *data, size_t len, unsigned char *out) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);       /* weak hash */
    MD5(data, len, out);                            /* one-shot weak hash */
    SHA1(data, len, out);                           /* weak hash */
}

void cipher_setup(void) {
    const EVP_CIPHER *c1 = EVP_des_ecb();           /* DES-56, broken */
    const EVP_CIPHER *c2 = EVP_aes_256_gcm();       /* ok, AEAD */
    const EVP_CIPHER *c3 = EVP_get_cipherbyname("des-cbc");  /* by-name DES */
}

void keygen(void) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);   /* RSA-2048, quantum-broken */
    RSA_generate_key_ex(r, 1024, e, NULL);                   /* RSA-1024 */
    DH *dh = DH_generate_parameters(512, 2, NULL, NULL);     /* weak 512-bit DH */
}

void modern(unsigned char *ct, const unsigned char *m, unsigned long long mlen,
            const unsigned char *n, const unsigned char *k) {
    crypto_secretbox_easy(ct, m, mlen, n, k);       /* libsodium XSalsa20-Poly1305 */
    crypto_sign_ed25519(ct, NULL, m, mlen, k);      /* Ed25519 */
}
