#include "ake.h"
#include "fips202.h"
#include <oqs/sha3_ops.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

/* Having generated 32 random bytes, you should call this function to
 * finalize the generated key.
 */
static void c25519_prepare(uint8_t *key)
{
	key[0] &= 0xf8;
	key[31] &= 0x7f;
	key[31] |= 0x40;
}

int ake_keygen_lkey_A(uint8_t *lpka, uint8_t *lska) {
    
    uint8_t seed1[SEED_BYTES];
    RAND_bytes(seed1, SEED_BYTES);

    size_t pubdata_len = 0;

    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    memcpy(lska, seed1, SEED_BYTES);
    c25519_prepare(lska);
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                            lska,
                                            SEED_BYTES);

    if (!EVP_PKEY_get_octet_string_param(privk,
                                         OSSL_PKEY_PARAM_PUB_KEY,
                                         lpka,
                                         32,
                                         &pubdata_len)) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() failed\n");
        exit(-1);
    }
    
    return 0;
}

int ake_keygen_lkey_B(OQS_KEM* kem, uint8_t *lpkb, uint8_t *lskb) {
    if (kem->keypair(lpkb, lskb) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_send_A(OQS_KEM* kem_cpa, OQS_KEM* kem_cca, const uint8_t *lpka, const uint8_t *lska, 
                const uint8_t *lpkb, uint8_t *epka, uint8_t *send, size_t *sendlen, uint8_t *st) {
    uint8_t buf[SEED_BYTES + SEED_BYTES], r[SEED_BYTES];
    uint8_t ct[kem_cca->length_ciphertext], ss[kem_cca->length_shared_secret];
    uint8_t eska[kem_cpa->length_secret_key];

    OQS_randombytes(buf, SEED_BYTES);
    memcpy(buf + SEED_BYTES, lska, SEED_BYTES);
    sha3_256(r, buf, SEED_BYTES + SEED_BYTES);
    
    if (kem_cpa->cpa_keypair_derand(epka, eska, r) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }

    if (kem_cca->encaps(ct, ss, lpkb) != OQS_SUCCESS) {
        printf("Error encapsulating by kem_cca. Exiting.\n");
		exit(-1);
    }
    
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t sigmessage[mlen];
    size_t tmplen = 0;
    memcpy(sigmessage, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(sigmessage + tmplen, ct, kem_cca->length_ciphertext);
    
    /*if (sig->sign(sigma, &siglen, sigmessage, mlen, lska)) {
        printf("Error signing by B. Exiting.\n");
		exit(-1);
    }*/

    size_t sig_len;
    unsigned char *sig_value = NULL;
    EVP_MD_CTX *sign_context = NULL;

    /* Create a signature context */
    sign_context = EVP_MD_CTX_new();
    if (sign_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        exit(-1);
    }

    /*
     * Initialize the sign context using an ED25519 private key
     * Notice that the digest name must NOT be used.
     * In this demo we don't specify any additional parameters via
     * OSSL_PARAM, which means it will use default values.
     * For more information, refer to doc/man7/EVP_SIGNATURE-ED25519.pod
     * "ED25519 and ED448 Signature Parameters"
     */
    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                                lska,
                                                SEED_BYTES);
    if (!EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx, NULL, privk, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        exit(-1);
    }

    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (!EVP_DigestSign(sign_context, NULL, &sig_len, sigmessage, mlen)) {
        fprintf(stderr, "EVP_DigestSign using NULL buffer failed.\n");
        exit(-1);
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "OPENSSL_malloc failed.\n");
        exit(-1);
    }
    
    if (!EVP_DigestSign(sign_context, sig_value, &sig_len, sigmessage, mlen)) {
        fprintf(stderr, "EVP_DigestSign failed.\n");
        exit(-1);
    }

    /*memcpy(send, epka, kem_cpa->length_public_key);
    memcpy(send + kem_cpa->length_public_key, ct, kem_cca->length_ciphertext);*/
    memcpy(send, sigmessage, mlen);
    memcpy(send + mlen, sig_value, sig_len);
    *sendlen = kem_cpa->length_public_key + kem_cca->length_ciphertext + sig_len;

    //store r0|ss|ct into state
    memcpy(st, buf, SEED_BYTES);
    memcpy(st + SEED_BYTES, ss, kem_cca->length_shared_secret); 
    memcpy(st + SEED_BYTES + kem_cca->length_shared_secret, ct, kem_cca->length_ciphertext); 

    return 0;
}

int ake_send_B(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cca->length_ciphertext], ss1[kem_cca->length_shared_secret];
    uint8_t ct2[kem_cpa->length_ciphertext], ss2[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t epka[kem_cpa->length_public_key];
    size_t tmplen2 = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t sigma[recvlen - tmplen2];

    memcpy(epka, recv, kem_cpa->length_public_key);
    memcpy(ct1, recv + kem_cpa->length_public_key, kem_cca->length_ciphertext);
    memcpy(sigma, recv + tmplen2, recvlen - tmplen2);

    uint8_t sigmessage[mlen];
    size_t tmplen = 0;
    memcpy(sigmessage, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(sigmessage + tmplen, ct1, kem_cca->length_ciphertext);
    
    /*if (sig->verify(sigmessage, mlen, sigma, recvlen - tmplen2, lpka) != OQS_SUCCESS) {
        printf("Verification fails.\n");
		exit(-1);
    }*/

   EVP_MD_CTX *verify_context = NULL;

    /*
     * Make a verify signature context to hold temporary state
     * during signature verification
     */
    verify_context = EVP_MD_CTX_new();
    if (verify_context == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed.\n");
        exit(-1);
    }
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pubk = NULL;
    pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "ED25519", NULL, lpka, 32);
    
    /* Initialize the verify context with a ED25519 public key */
    if (!EVP_DigestVerifyInit_ex(verify_context, NULL, NULL,
                                 libctx, NULL, pubk, NULL)) {
        fprintf(stderr, "EVP_DigestVerifyInit_ex failed.\n");
        EVP_MD_CTX_free(verify_context);
        exit(-1);
    }
    /*
     * ED25519 only supports the one shot interface using EVP_DigestVerify()
     * The streaming EVP_DigestVerifyUpdate() API is not supported.
     */
    if (!EVP_DigestVerify(verify_context, sigma, 2*SEED_BYTES,
                          sigmessage, mlen)) {
        fprintf(stderr, "EVP_DigestVerify() failed.\n");
        EVP_MD_CTX_free(verify_context);
        exit(-1);
    }

    //if (kem_cpa->encaps(ct2, ss2, recv)) {
    if (kem_cpa->cpa_encaps(ct2, ss2, epka)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }
    
    kem_cca->decaps(ss1, ct1, lskb);
    

    size_t len = 0, len2=0;
    len2 = SEED_BYTES + kem_cca->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    memcpy(hash_k_input, lpka, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(hash_k_input + len, lpkb, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;

    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(hash_k_input + len, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(hash_k_input + len, ss2, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss1, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    memcpy(send, ct2, kem_cpa->length_ciphertext);
    *sendlen = kem_cpa->length_ciphertext;

    return 0;

}

int ake_receive_A(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *lpkb, const uint8_t *st, const uint8_t *recv, 
    uint8_t *k) {
    
    uint8_t epka[kem_cpa->length_public_key], eska[kem_cpa->length_secret_key], ss_cpa[kem_cpa->length_shared_secret];
    uint8_t ct_cca[kem_cca->length_ciphertext], ss_cca[kem_cca->length_shared_secret];
    uint8_t buf[SEED_BYTES + SEED_BYTES], r[SEED_BYTES];

    memcpy(buf, st, SEED_BYTES);
    memcpy(ss_cca, st + SEED_BYTES, kem_cca->length_shared_secret);
    memcpy(ct_cca, st + SEED_BYTES + kem_cca->length_shared_secret, kem_cca->length_ciphertext);
    memcpy(buf + SEED_BYTES, lska, SEED_BYTES);
    sha3_256(r, buf, SEED_BYTES + SEED_BYTES);
    if (kem_cpa->cpa_keypair_derand(epka, eska, r) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }
    kem_cpa->cpa_decaps(ss_cpa, recv, eska);

    size_t len = 0, len2=0;
    len2 = SEED_BYTES + kem_cca->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    memcpy(hash_k_input, lpka, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(hash_k_input + len, lpkb, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;

    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, recv, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(hash_k_input + len, ct_cca, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(hash_k_input + len, ss_cpa, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss_cca, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    return 0;
}



