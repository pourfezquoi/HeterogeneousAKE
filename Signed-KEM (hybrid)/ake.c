#include "ake.h"
#include "fips202.h"
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

static void c25519_prepare(uint8_t *key)
{
	key[0] &= 0xf8;
	key[31] &= 0x7f;
	key[31] |= 0x40;
}


int ake_keygen_lkey_A(uint8_t *lpka, uint8_t *lska) {
    /*if (kem->keypair(lpka, lska) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }*/
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

int ake_keygen_lkey_B(uint8_t *lpkb, uint8_t *lskb) {
    /*if (sig->keypair(lpkb, lskb) != OQS_SUCCESS) {
        printf("Error creating long term key for B. Exiting.\n");
		exit(-1);
    }*/
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

int ake_send_A(OQS_KEM* kem_cpa, uint8_t *send, uint8_t *epka, uint8_t *eska, const uint8_t *lpka, const uint8_t *lska, const uint8_t *lpkb) {
    //if (kem->keypair(epka, eska) != OQS_SUCCESS) {
    /*if (kem->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }*/
    //EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    /*eska = EVP_PKEY_Q_keygen(libctx, NULL, "X25519");
    size_t pubk_data_len = 0;
    EVP_PKEY_get_octet_string_param(eska, OSSL_PKEY_PARAM_PUB_KEY, epka, SEED_BYTES, &pubk_data_len);
    */
    if (kem_cpa->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }

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
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                                lska,
                                                SEED_BYTES);
    if (!EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx, NULL, privk, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        exit(-1);
    }

    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (!EVP_DigestSign(sign_context, NULL, &sig_len, epka, kem_cpa->length_public_key)) {
        fprintf(stderr, "EVP_DigestSign using NULL buffer failed.\n");
        exit(-1);
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "OPENSSL_malloc failed.\n");
        exit(-1);
    }
    
    if (!EVP_DigestSign(sign_context, sig_value, &sig_len, epka, kem_cpa->length_public_key)) {
        fprintf(stderr, "EVP_DigestSign failed.\n");
        exit(-1);
    }

    memcpy(send, epka, kem_cpa->length_public_key);
    memcpy(send + kem_cpa->length_public_key, sig_value, sig_len);
    return 0;
}

int ake_send_B(OQS_KEM* kem_cpa, const uint8_t *lpka, const uint8_t *recv, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cpa->length_ciphertext], ss1[kem_cpa->length_shared_secret];
    //EVP_PKEY *eskb;
    OSSL_LIB_CTX *libctx = NULL;
    /*uint8_t epkb[SEED_BYTES];

    eskb = EVP_PKEY_Q_keygen(libctx, NULL, "X25519");
    size_t pubk_data_len = 0;
    EVP_PKEY_get_octet_string_param(eskb, OSSL_PKEY_PARAM_PUB_KEY, epkb, SEED_BYTES, &pubk_data_len);
    */
    uint8_t sigma[2*SEED_BYTES];
    uint8_t epka[kem_cpa->length_public_key];
    

    size_t mlen = kem_cpa->length_public_key;
    //uint8_t sigmessage[mlen];
    size_t mlen2 = mlen + kem_cpa->length_ciphertext;
    uint8_t buf[mlen2];

    memcpy(epka, recv, kem_cpa->length_public_key);
    memcpy(sigma, recv + kem_cpa->length_public_key, 2*SEED_BYTES);
    
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
    libctx = NULL;
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
                          epka, mlen)) {
        fprintf(stderr, "EVP_DigestVerify() failed.\n");
        EVP_MD_CTX_free(verify_context);
        exit(-1);
    }

    if (kem_cpa->cpa_encaps(ct1, ss1, epka)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }

    memcpy(buf, epka, mlen);
    memcpy(buf + mlen, ct1, kem_cpa->length_ciphertext);

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
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                                lskb,
                                                SEED_BYTES);
    if (!EVP_DigestSignInit_ex(sign_context, NULL, NULL, libctx, NULL, privk, NULL)) {
        fprintf(stderr, "EVP_DigestSignInit_ex failed.\n");
        exit(-1);
    }

    /* Calculate the required size for the signature by passing a NULL buffer. */
    if (!EVP_DigestSign(sign_context, NULL, &sig_len, buf, mlen2)) {
        fprintf(stderr, "EVP_DigestSign using NULL buffer failed.\n");
        exit(-1);
    }
    sig_value = OPENSSL_malloc(sig_len);
    if (sig_value == NULL) {
        fprintf(stderr, "OPENSSL_malloc failed.\n");
        exit(-1);
    }
    
    if (!EVP_DigestSign(sign_context, sig_value, &sig_len, buf, mlen2)) {
        fprintf(stderr, "EVP_DigestSign failed.\n");
        exit(-1);
    }

    uint8_t hash_k_input[mlen2+kem_cpa->length_shared_secret];
    
    memcpy(hash_k_input, buf, mlen2);    
    memcpy(hash_k_input + mlen2, ss1, kem_cpa->length_shared_secret);
   
    shake256(k, SESSION_KEY_LEN, hash_k_input, mlen2+kem_cpa->length_shared_secret);
    
    *sendlen = kem_cpa->length_ciphertext + sig_len;
    //send = (uint8_t *) calloc (*sendlen, sizeof(uint8_t));

    memcpy(send, ct1, kem_cpa->length_ciphertext);
    memcpy(send + kem_cpa->length_ciphertext, sig_value, sig_len);

    return 0;

}

int ake_receive_A(OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *epka, uint8_t *eska, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, uint8_t *k) {

    
    uint8_t sigma[2*SEED_BYTES], ct1[kem_cpa->length_ciphertext], ss1[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cpa->length_ciphertext, len=0;
    uint8_t buf[mlen];
    memcpy(ct1, recv, kem_cpa->length_ciphertext);
    memcpy(sigma, recv + kem_cpa->length_ciphertext, 2*SEED_BYTES);

    memcpy(buf, epka, kem_cpa->length_public_key);
    len = kem_cpa->length_public_key;
    memcpy(buf + len, ct1, kem_cpa->length_ciphertext);
    //len = len + kem_cpa->length_ciphertext;
    
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

    kem_cpa->cpa_decaps(ss1, ct1, eska);

    uint8_t hash_k_input[mlen+kem_cpa->length_shared_secret];
    
    memcpy(hash_k_input, buf, mlen);    
    memcpy(hash_k_input + mlen, ss1, kem_cpa->length_shared_secret);
   
    shake256(k, SESSION_KEY_LEN, hash_k_input, mlen + kem_cpa->length_shared_secret);
    
    return 0;
}



