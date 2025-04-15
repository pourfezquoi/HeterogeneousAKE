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

int ake_keygen_lkey_A(OQS_KEM* kem, uint8_t *lpka, uint8_t *lska) {
    if (kem->keypair(lpka, lska) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_keygen_lkey_B(uint8_t *lpkb, uint8_t *lskb) {
    uint8_t seed1[SEED_BYTES];
    RAND_bytes(seed1, SEED_BYTES);

    size_t pubdata_len = 0;

    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    memcpy(lskb, seed1, SEED_BYTES);
    c25519_prepare(lskb);
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                            lskb,
                                            SEED_BYTES);

    if (!EVP_PKEY_get_octet_string_param(privk,
                                         OSSL_PKEY_PARAM_PUB_KEY,
                                         lpkb,
                                         32,
                                         &pubdata_len)) {
        fprintf(stderr, "EVP_PKEY_get_octet_string_param() failed\n");
        exit(-1);
    }
    return 0;
}

int ake_send_A(OQS_KEM* kem, uint8_t *epka, uint8_t *eska) {
    //if (kem->keypair(epka, eska) != OQS_SUCCESS) {
    if (kem->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_send_B(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, const uint8_t *recv, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cca->length_ciphertext], ss1[kem_cca->length_shared_secret];
    uint8_t ct2[kem_cpa->length_ciphertext], ss2[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext + kem_cpa->length_ciphertext;
    uint8_t buf[mlen];
    size_t tmplen = 0;
    
    if (kem_cca->encaps(ct1, ss1, lpka) != OQS_SUCCESS) {
        printf("Error encapsulating by kem_cca. Exiting.\n");
		exit(-1);
    }
    //if (kem_cpa->encaps(ct2, ss2, recv)) {
    if (kem_cpa->cpa_encaps(ct2, ss2, recv)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }
    
    memcpy(buf, recv, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(buf + tmplen, ct1, kem_cca->length_ciphertext);
    tmplen = tmplen + kem_cca->length_ciphertext;
    memcpy(buf + tmplen, ct2, kem_cpa->length_ciphertext);
    /*if (sig->sign(sigma, &siglen, buf, mlen, lskb)) {
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
                                                lskb,
                                                SEED_BYTES);
    if (!EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx, NULL, privk, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        exit(-1);
    }

    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (!EVP_DigestSign(sign_context, NULL, &sig_len, buf, mlen)) {
        fprintf(stderr, "EVP_DigestSign using NULL buffer failed.\n");
        exit(-1);
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "OPENSSL_malloc failed.\n");
        exit(-1);
    }
    
    if (!EVP_DigestSign(sign_context, sig_value, &sig_len, buf, mlen)) {
        fprintf(stderr, "EVP_DigestSign failed.\n");
        exit(-1);
    }


    size_t len = 0, len2=0;
    len2 = kem_cca->length_public_key + SEED_BYTES + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;
    
    memcpy(hash_k_input + len, lpkb, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, recv, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;
    
    memcpy(hash_k_input + len, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;
    
    memcpy(hash_k_input + len, ss2, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss1, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    /*printf("sendb len=%d, hash_k_input=\n",len);
    for(int i=0;i<len;i++){
        printf("%x, ", hash_k_input[i]);
    }
    printf("\n\n");*/
    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    *sendlen = kem_cca->length_ciphertext + kem_cpa->length_ciphertext + sig_len;
    //send = (uint8_t *) calloc (*sendlen, sizeof(uint8_t));

    len = 0;
    memcpy(send, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(send + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(send + len, sig_value, sig_len);
    len = len + sig_len;

    return 0;

}

int ake_receive_A(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *epka, const uint8_t *eska, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, uint8_t *k) {


    uint8_t ct_cca[kem_cca->length_ciphertext], ss_cca[kem_cca->length_shared_secret];
    uint8_t ct_cpa[kem_cpa->length_ciphertext], ss_cpa[kem_cpa->length_shared_secret];
    size_t len = 0;

    uint8_t sigma[2*SEED_BYTES];

    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext + kem_cpa->length_ciphertext;
    uint8_t buf[mlen];
    size_t tmplen = 0;
    
    memcpy(ct_cca, recv, kem_cca->length_ciphertext);
    len = kem_cca->length_ciphertext;
    memcpy(ct_cpa, recv + len, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(sigma, recv + len, recvlen - len);

    memcpy(buf, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(buf + tmplen, ct_cca, kem_cca->length_ciphertext);
    tmplen = tmplen + kem_cca->length_ciphertext;
    memcpy(buf + tmplen, ct_cpa, kem_cpa->length_ciphertext);
    /*if (sig->verify(buf, mlen, sigma, recvlen - len, lpkb) != OQS_SUCCESS) {
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
    pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "ED25519", NULL, lpkb, 32);
    
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
                          buf, mlen)) {
        fprintf(stderr, "EVP_DigestVerify() failed.\n");
        EVP_MD_CTX_free(verify_context);
        exit(-1);
    }

    //kem_cpa->decaps(ss_cpa, ct_cpa, eska);
    kem_cpa->cpa_decaps(ss_cpa, ct_cpa, eska);

    kem_cca->decaps(ss_cca, ct_cca, lska);

    len = 0;
    size_t len2=0;
    len2 = kem_cca->length_public_key + SEED_BYTES + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;
    
    memcpy(hash_k_input + len, lpkb, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct_cpa, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;
    
    memcpy(hash_k_input + len, ct_cca, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;
    
    memcpy(hash_k_input + len, ss_cpa, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss_cca, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;
    
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    shake256(k, SESSION_KEY_LEN, hash_k_input, len);


    return 0;
}



