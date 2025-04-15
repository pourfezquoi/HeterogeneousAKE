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

static void hash(const unsigned char *message, size_t message_len, unsigned char *digest){
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, message, message_len);
  //digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  unsigned int len = 0;
  EVP_DigestFinal_ex(mdctx, digest, &len);

	EVP_MD_CTX_free(mdctx);
}

int ake_keygen_lkey_A(uint8_t *lpka, uint8_t *lska) {
    /*if (kem->keypair(lpka, lska) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }*/
    uint8_t seed1[SEED_BYTES];
    RAND_bytes(seed1, SEED_BYTES);
    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    memcpy(lska, seed1, SEED_BYTES);
    c25519_prepare(lska);
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                                lska,
                                                SEED_BYTES);
    size_t pubk_data_len = 0;
    EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, lpka, SEED_BYTES, &pubk_data_len);
    
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

int ake_send_A(uint8_t *epka, uint8_t *eska) {
    //if (kem->keypair(epka, eska) != OQS_SUCCESS) {
    /*if (kem->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }*/
    uint8_t seed1[SEED_BYTES];
    RAND_bytes(seed1, SEED_BYTES);
    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    memcpy(eska, seed1, SEED_BYTES);
    c25519_prepare(eska);
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                                eska,
                                                SEED_BYTES);
    size_t pubk_data_len = 0;
    EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, epka, SEED_BYTES, &pubk_data_len);
    
    return 0;
}

int ake_send_B(const uint8_t *lpka, const uint8_t *recv, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[SEED_BYTES], ss1[SESSION_KEY_LEN];
    uint8_t ct2[SEED_BYTES], ss2[SESSION_KEY_LEN];
    
    size_t mlen = 3*SEED_BYTES;
    uint8_t buf[mlen];
    //uint8_t sigma[2*SEED_BYTES];
    
    /*if (kem_cca->encaps(ct1, ss1, lpka) != OQS_SUCCESS) {
        printf("Error encapsulating by kem_cca. Exiting.\n");
		exit(-1);
    }*/
    EVP_PKEY *privk;
    OSSL_LIB_CTX *libctx = NULL;

    privk = EVP_PKEY_Q_keygen(libctx, NULL, "X25519");
    size_t pubk_data_len = 0;
    EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, ct1, SEED_BYTES, &pubk_data_len);
    EVP_PKEY *remote_peer_pubk = NULL;
    remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, lpka, 32);
    EVP_PKEY_CTX *ctx = NULL;
    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
    /* Initialize derivation process. */
    EVP_PKEY_derive_init(ctx);
    /* Configure each peer with the other peer's public key. */
    EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    /* Derive the shared secret. */
    uint8_t shared1[SEED_BYTES];
    EVP_PKEY_derive(ctx, shared1, &secret_len);
    unsigned char message[3*SEED_BYTES];
    memcpy(message, shared1, SEED_BYTES);
    memcpy(message+SEED_BYTES, ct1, SEED_BYTES);
    memcpy(message+2*SEED_BYTES, lpka, SEED_BYTES);
    hash(message, 3*SEED_BYTES, ss1);

    //if (kem_cpa->encaps(ct2, ss2, recv)) {
    /*if (kem_cpa->cpa_encaps(ct2, ss2, recv)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }*/
    
    privk = EVP_PKEY_Q_keygen(libctx, NULL, "X25519");
    
    EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, ct2, SEED_BYTES, &pubk_data_len);
    remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, recv, 32);
    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
    /* Initialize derivation process. */
    EVP_PKEY_derive_init(ctx);
    /* Configure each peer with the other peer's public key. */
    EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    /* Derive the shared secret. */
    EVP_PKEY_derive(ctx, ss2, &secret_len);
    
    memcpy(buf, recv, SEED_BYTES);
    memcpy(buf + SEED_BYTES, ct1, SEED_BYTES);
    memcpy(buf + 2*SEED_BYTES, ct2, SEED_BYTES);
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
    libctx = NULL;
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
    len2 = SEED_BYTES + SEED_BYTES + SEED_BYTES + 
            SEED_BYTES + SEED_BYTES + SEED_BYTES + SEED_BYTES;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, lpkb, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, recv, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(hash_k_input + len, ct2, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ct1, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ss2, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ss1, SEED_BYTES);
    len = len + SEED_BYTES;

    /*printf("sendb len=%d, hash_k_input=\n",len);
    for(int i=0;i<len;i++){
        printf("%x, ", hash_k_input[i]);
    }
    printf("\n\n");*/
    //shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    hash(hash_k_input, 7*SEED_BYTES, k);
    
    *sendlen = SEED_BYTES + SEED_BYTES + sig_len;
    //send = (uint8_t *) calloc (*sendlen, sizeof(uint8_t));

    len = 0;
    memcpy(send, ct1, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(send + len, ct2, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(send + len, sig_value, sig_len);
    len = len + sig_len;

    return 0;

}

int ake_receive_A(const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *epka, const uint8_t *eska, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, uint8_t *k) {


    uint8_t ct_cca[SEED_BYTES], ss_cca[SESSION_KEY_LEN];
    uint8_t ct_cpa[SEED_BYTES], ss_cpa[SESSION_KEY_LEN];
    size_t len = 0;

    uint8_t sigma[2*SEED_BYTES];

    size_t mlen = 3*SEED_BYTES;
    uint8_t buf[mlen];
    
    memcpy(ct_cca, recv, SEED_BYTES);
    len = SEED_BYTES;
    memcpy(ct_cpa, recv + len, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(sigma, recv + len, 2*SEED_BYTES);

    memcpy(buf, epka, mlen);
    memcpy(buf + SEED_BYTES, ct_cca, SEED_BYTES);
    memcpy(buf + 2*SEED_BYTES, ct_cpa, SEED_BYTES);
    
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

    //kem_cpa->cpa_decaps(ss_cpa, ct_cpa, eska);
    EVP_PKEY *privk;
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                                eska,
                                                SEED_BYTES);
    
    libctx = NULL;
   
    EVP_PKEY *remote_peer_pubk = NULL;
    remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, ct_cpa, 32);
    EVP_PKEY_CTX *ctx = NULL;
    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
    /* Initialize derivation process. */
    EVP_PKEY_derive_init(ctx);
    /* Configure each peer with the other peer's public key. */
    EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    /* Derive the shared secret. */
    EVP_PKEY_derive(ctx, ss_cpa, &secret_len);

    //kem_cca->decaps(ss_cca, ct_cca, lska);
    privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                                lska,
                                                SEED_BYTES);
    remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, ct_cca, 32);
    /* Create key exchange context. */
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
    /* Initialize derivation process. */
    EVP_PKEY_derive_init(ctx);
    /* Configure each peer with the other peer's public key. */
    EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    /* Derive the shared secret. */
    uint8_t shared1[SEED_BYTES];
    EVP_PKEY_derive(ctx, shared1, &secret_len);
    unsigned char message[3*SEED_BYTES];
    memcpy(message, shared1, SEED_BYTES);
    memcpy(message+SEED_BYTES, ct_cca, SEED_BYTES);
    memcpy(message+2*SEED_BYTES, lpka, SEED_BYTES);
    hash(message, 3*SEED_BYTES, ss_cca);

    len = 0;
    size_t len2=0;
    len2 = 7*SEED_BYTES;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, lpkb, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, epka, SEED_BYTES);
    len = len + SEED_BYTES;

    memcpy(hash_k_input + len, ct_cpa, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ct_cca, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ss_cpa, SEED_BYTES);
    len = len + SEED_BYTES;
    
    memcpy(hash_k_input + len, ss_cca, SEED_BYTES);
    len = len + SEED_BYTES;
    
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    //shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    hash(hash_k_input, 7*SEED_BYTES, k);

    return 0;
}



