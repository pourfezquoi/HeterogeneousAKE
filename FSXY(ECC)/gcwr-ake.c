#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include "compact25519.c"
#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "gcwr-ake.h"

int is_mceliece(OQS_KEM* kem) {
  return strstr(kem->method_name, "McEliece") != NULL ? 1 : 0;
}

void concat_keys(const uint8_t *key1, const uint8_t *key2, const uint8_t *key3,
                 size_t length, uint8_t *out) {
  memcpy(out, key1, length);
  memcpy(out + length, key2, length);
  memcpy(out + 2*length, key3, length);
}

void concat_sid(
                const char UA[PID_LENGTH],
                const char UB[PID_LENGTH],
                const uint8_t *ekA1,
                const uint8_t *ekB1,
                const uint8_t *cA1,
                const uint8_t *ekA2,
                const uint8_t *cB1,
                const uint8_t *cB2,
                uint8_t *sid) {

  memcpy(sid, UA, PID_LENGTH);
  memcpy(sid + PID_LENGTH, UB, PID_LENGTH);
  memcpy(sid + 2*PID_LENGTH, ekA1, X25519_KEY_SIZE);
  memcpy(sid + 2*PID_LENGTH + X25519_KEY_SIZE, ekA2, X25519_KEY_SIZE);
  memcpy(sid + 2*PID_LENGTH + 2*X25519_KEY_SIZE, ekB1, X25519_KEY_SIZE);
  memcpy(sid + 2*PID_LENGTH + 3*X25519_KEY_SIZE, cA1, X25519_KEY_SIZE);
  memcpy(sid + 2*PID_LENGTH + 3*X25519_KEY_SIZE + X25519_KEY_SIZE, cB1, X25519_KEY_SIZE);
  memcpy(sid + 2*PID_LENGTH + 3*X25519_KEY_SIZE + 2*X25519_KEY_SIZE, cB2, X25519_KEY_SIZE);
}

void gen_sk(uint8_t *sid, uint8_t *concat_keys, size_t length_sid, size_t length_concat_keys, uint8_t *sk){
  uint8_t temp[length_sid + length_concat_keys]; 
  memcpy(temp, concat_keys, length_concat_keys);
  memcpy(temp + length_concat_keys, sid, length_sid);
  //OQS_SHA3_sha3_256(sk, temp, length_sid + length_concat_keys);
  /*struct sha512_state hasher;
  sha512_init(&hasher);
  sha512_final(&hasher, temp, length_sid + length_concat_keys);
  sha512_get(&hasher, sk, 0, X25519_KEY_SIZE);
  OQS_MEM_secure_free(temp, length_sid + length_concat_keys);*/
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, temp, length_sid + length_concat_keys);
  //sk = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  unsigned int len = 0;
  EVP_DigestFinal_ex(mdctx, sk, &len);

	EVP_MD_CTX_free(mdctx);
}

void hash_key(const unsigned char *message, size_t message_len, unsigned char *digest){
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, message, message_len);
  //digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
  unsigned int len = 0;
  EVP_DigestFinal_ex(mdctx, digest, &len);

	EVP_MD_CTX_free(mdctx);
}

void ake_init(
              uint8_t* ekB1,
              uint8_t* cA1,
              uint8_t* kA1,
              uint8_t* ekA2,
              uint8_t* dkA2) {

  /*uint8_t *rA1 = malloc(kem->length_shared_secret);
  OQS_randombytes(rA1, kem->length_shared_secret);

  uint8_t *tempA1 = malloc(kem->length_shared_secret + kem->length_secret_key);
  uint8_t *hashA1 = malloc(kem->length_shared_secret);
  memcpy(tempA1, rA1, kem->length_shared_secret);
  memcpy(tempA1 + kem->length_shared_secret, dkA1, kem->length_secret_key);
  OQS_SHA3_sha3_256(hashA1, tempA1, kem->length_shared_secret + kem->length_secret_key);
  */
  /*uint8_t *coins = malloc(kem->length_coins);
  if (is_mceliece(kem)) {
    kem->gen_e(coins);
  } else {
    OQS_randombytes(coins, kem->length_coins);
  }

  OQS_KEM_encaps(kem, cA1, kA1, ekB1, coins);*/
  uint8_t seed1[X25519_KEY_SIZE];
  RAND_bytes(seed1, X25519_KEY_SIZE);
  /*uint8_t sec1[X25519_KEY_SIZE];
  uint8_t shared1[X25519_KEY_SIZE];
  //uint8_t pub1[X25519_KEY_SIZE]; cA1=pub1
  compact_x25519_keygen(sec1, cA1, seed1);
  compact_x25519_shared(shared1, sec1, ekB1);
  compact_x25519_derive_encryption_key(kA1, X25519_KEY_SIZE, shared1, cA1, ekB1);*/
  EVP_PKEY *privk;
  OSSL_LIB_CTX *libctx = NULL;
  c25519_prepare(seed1);
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            seed1,
                                            X25519_KEY_SIZE);
  size_t pubk_data_len = 0;
  EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, cA1, X25519_KEY_SIZE, &pubk_data_len);
  EVP_PKEY *remote_peer_pubk = NULL;
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, ekB1, 32);
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
  uint8_t shared1[X25519_KEY_SIZE];
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  unsigned char message[3*X25519_KEY_SIZE];
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cA1, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekB1, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kA1);

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(remote_peer_pubk);
  EVP_PKEY_free(privk);
  
  
  
  /*uint8_t shared_secret[X25519_SHARED_SIZE], 
  const uint8_t my_private_key[X25519_KEY_SIZE], 
  const uint8_t their_public_key[X25519_KEY_SIZE]*/



  uint8_t seed2[X25519_KEY_SIZE];
  RAND_bytes(seed2, X25519_KEY_SIZE);
  //uint8_t sec1[X25519_KEY_SIZE];
  //uint8_t pub1[X25519_KEY_SIZE];
  memcpy(dkA2, seed2, X25519_KEY_SIZE);
  c25519_prepare(dkA2);
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            dkA2,
                                            X25519_KEY_SIZE);
  EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, ekA2, X25519_KEY_SIZE, &pubk_data_len);
  
  //compact_x25519_keygen(dkA2, ekA2, seed2);
  //OQS_KEM_keypair(kem, ekA2, dkA2);

  /*OQS_MEM_secure_free(tempA1, kem->length_shared_secret + kem->length_secret_key);
  OQS_MEM_secure_free(hashA1, kem->length_shared_secret);
  OQS_MEM_secure_free(rA1, kem->length_shared_secret);
  OQS_MEM_secure_free(coins, kem->length_coins);*/
}

void ake_algB(
              const uint8_t* ekA1,
              const uint8_t* ekA2,
              const uint8_t* dkB1,
              uint8_t* kB1,
              uint8_t* kB2,
              uint8_t* cA1,
              uint8_t* cB1,
              uint8_t* cB2,
              uint8_t* kA1,
              uint8_t* ekB1,
              uint8_t* skB) {

  /*uint8_t *rB1 = malloc(kem->length_shared_secret);
  uint8_t *coins = malloc(kem->length_coins);

  const size_t sid_length = 2*PID_LENGTH + 3*kem->length_public_key + 3*kem->length_ciphertext;

  OQS_randombytes(rB1, kem->length_shared_secret);

  uint8_t *tempB1 = malloc(kem->length_shared_secret + kem->length_secret_key);
  uint8_t *hashB1 = malloc(kem->length_shared_secret);
  uint8_t *sid = malloc(sid_length);
  memcpy(tempB1, rB1, kem->length_shared_secret);
  memcpy(tempB1 + kem->length_shared_secret, dkB1, kem->length_secret_key);
  OQS_SHA3_sha3_256(hashB1, tempB1, kem->length_shared_secret + kem->length_secret_key);

  if (is_mceliece(kem)) {
    kem->gen_e(coins);
  } else {
    OQS_randombytes(coins, kem->length_coins);
  }
  OQS_KEM_encaps(kem, cB1, kB1, ekA1, coins);*/
  uint8_t seed1[X25519_KEY_SIZE];
  RAND_bytes(seed1, X25519_KEY_SIZE);
  /*uint8_t sec1[X25519_KEY_SIZE];
  uint8_t shared1[X25519_KEY_SIZE];
  //uint8_t pub1[X25519_KEY_SIZE]; cA1=pub1
  compact_x25519_keygen(sec1, cB1, seed1);
  compact_x25519_shared(shared1, sec1, ekA1);
  compact_x25519_derive_encryption_key(kB1, X25519_KEY_SIZE, shared1, cB1, ekA1);*/
  
  EVP_PKEY *privk;
  OSSL_LIB_CTX *libctx = NULL;
  c25519_prepare(seed1);
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            seed1,
                                            X25519_KEY_SIZE);
  size_t pubk_data_len = 0;
  EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, cB1, X25519_KEY_SIZE, &pubk_data_len);
  EVP_PKEY *remote_peer_pubk = NULL;
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, ekA1, 32);
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
  uint8_t shared1[X25519_KEY_SIZE];
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  unsigned char message[3*X25519_KEY_SIZE];
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cB1, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekA1, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kB1);
  
  uint8_t seed2[X25519_KEY_SIZE];
  RAND_bytes(seed2, X25519_KEY_SIZE);
  /*uint8_t sec2[X25519_KEY_SIZE];
  uint8_t shared2[X25519_KEY_SIZE];
  //uint8_t pub1[X25519_KEY_SIZE]; cA1=pub1
  compact_x25519_keygen(sec2, cB2, seed1);
  compact_x25519_shared(shared2, sec2, ekA2);
  compact_x25519_derive_encryption_key(kB2, X25519_KEY_SIZE, shared2, cB2, ekA2);*/
  c25519_prepare(seed2);
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            seed2,
                                            X25519_KEY_SIZE);
  EVP_PKEY_get_octet_string_param(privk, OSSL_PKEY_PARAM_PUB_KEY, cB2, X25519_KEY_SIZE, &pubk_data_len);
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, ekA2, 32);
  /* Create key exchange context. */
  ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
  /* Initialize derivation process. */
  EVP_PKEY_derive_init(ctx);
  /* Configure each peer with the other peer's public key. */
  EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
  EVP_PKEY_derive(ctx, NULL, &secret_len);
  /* Derive the shared secret. */
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cB2, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekA2, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kB2);

  //OQS_KEM_decaps(kem, kA1, cA1, dkB1);
  /*uint8_t shared3[X25519_KEY_SIZE];
  compact_x25519_shared(shared3, dkB1, cA1);
  compact_x25519_derive_encryption_key(kA1, X25519_KEY_SIZE, shared3, cA1, ekB1);*/
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            dkB1,
                                            X25519_KEY_SIZE);
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, cA1, 32);
  /* Create key exchange context. */
  ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
  /* Initialize derivation process. */
  EVP_PKEY_derive_init(ctx);
  /* Configure each peer with the other peer's public key. */
  EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
  EVP_PKEY_derive(ctx, NULL, &secret_len);
  /* Derive the shared secret. */
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cA1, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekB1, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kA1);

  //uint8_t *concat_keysB = malloc(3*kem->length_shared_secret);
  uint8_t concat_keysB[3*X25519_KEY_SIZE]; //= malloc(3*X25519_KEY_SIZE);
  concat_keys(kA1, kB1, kB2, X25519_KEY_SIZE, concat_keysB);
  const size_t sid_length = 2*PID_LENGTH + 3*X25519_KEY_SIZE + 3*X25519_KEY_SIZE;
  uint8_t sid[sid_length]; //= malloc(sid_length);
  concat_sid(U_A, U_B, ekA1, ekB1, cA1, ekA2, cB1, cB2, sid);
  gen_sk(sid, concat_keysB, sid_length, 3*X25519_KEY_SIZE, skB);

  /*OQS_MEM_secure_free(concat_keysB, 3*kem->length_shared_secret);
  OQS_MEM_secure_free(tempB1, kem->length_shared_secret + kem->length_secret_key);
  OQS_MEM_secure_free(hashB1, kem->length_shared_secret);
  OQS_MEM_secure_free(rB1, kem->length_shared_secret);
  OQS_MEM_secure_free(coins, kem->length_coins);
  OQS_MEM_secure_free(sid, sid_length);*/
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(remote_peer_pubk);
  EVP_PKEY_free(privk);
}

void ake_algA(
              const uint8_t* cB1,
              const uint8_t* cB2,
              const uint8_t* dkA1,
              const uint8_t* dkA2,
              const uint8_t* kA1,
              const uint8_t* ekA1,
              const uint8_t* ekB1,
              const uint8_t* ekA2,
              const uint8_t* cA1,
              uint8_t* skB){

  /*const size_t sid_length = 2*PID_LENGTH + 3*kem->length_public_key + 3*kem->length_ciphertext;
  uint8_t *sid = malloc(sid_length);*/
  const size_t sid_length = 2*PID_LENGTH + 3*X25519_KEY_SIZE + 3*X25519_KEY_SIZE;
  uint8_t sid[sid_length];

  //uint8_t *kB1_prime = malloc(kem->length_shared_secret);
  uint8_t kB1_prime[X25519_KEY_SIZE];
  /*uint8_t shared1[X25519_KEY_SIZE];
  compact_x25519_shared(shared1, dkA1, cB1);
  compact_x25519_derive_encryption_key(kB1_prime, X25519_KEY_SIZE, shared1, cB1, ekA1);*/
  //OQS_KEM_decaps(kem, kB1_prime, cB1, dkA1);
  EVP_PKEY *privk;
  OSSL_LIB_CTX *libctx = NULL;
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            dkA1,
                                            X25519_KEY_SIZE);
  EVP_PKEY *remote_peer_pubk = NULL;
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, cB1, 32);
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
  uint8_t shared1[X25519_KEY_SIZE];
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  unsigned char message[3*X25519_KEY_SIZE];
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cB1, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekA1, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kB1_prime);

  //uint8_t *kB2_prime = malloc(kem->length_shared_secret);
  uint8_t kB2_prime[X25519_KEY_SIZE];
  /*uint8_t shared2[X25519_KEY_SIZE];
  compact_x25519_shared(shared2, dkA2, cB2);
  compact_x25519_derive_encryption_key(kB2_prime, X25519_KEY_SIZE, shared2, cB2, ekA2);*/
  //OQS_KEM_decaps(kem, kB2_prime, cB2, dkA2);
  privk = EVP_PKEY_new_raw_private_key_ex(libctx, "X25519", NULL,
                                            dkA2,
                                            X25519_KEY_SIZE);
  remote_peer_pubk = EVP_PKEY_new_raw_public_key_ex(libctx, "X25519", NULL, cB2, 32);
  /* Create key exchange context. */
  ctx = EVP_PKEY_CTX_new_from_pkey(libctx, privk, NULL);
  /* Initialize derivation process. */
  EVP_PKEY_derive_init(ctx);
  /* Configure each peer with the other peer's public key. */
  EVP_PKEY_derive_set_peer(ctx, remote_peer_pubk);
  EVP_PKEY_derive(ctx, NULL, &secret_len);
  EVP_PKEY_derive(ctx, shared1, &secret_len);
  memcpy(message, shared1, X25519_KEY_SIZE);
  memcpy(message+X25519_KEY_SIZE, cB2, X25519_KEY_SIZE);
  memcpy(message+2*X25519_KEY_SIZE, ekA2, X25519_KEY_SIZE);
  hash_key(message, 3*X25519_KEY_SIZE, kB2_prime);

  uint8_t concat_keysA[3*X25519_KEY_SIZE];// = malloc(3*X25519_KEY_SIZE);
  concat_keys(kA1, kB1_prime, kB2_prime, X25519_KEY_SIZE, concat_keysA);
  concat_sid(U_A, U_B, ekA1, ekB1, cA1, ekA2, cB1, cB2, sid);
  gen_sk(sid, concat_keysA, sid_length, 3*X25519_KEY_SIZE, skB);

  /*OQS_MEM_secure_free(concat_keysA, 3*kem->length_shared_secret);
  OQS_MEM_secure_free(kB1_prime, kem->length_shared_secret);
  OQS_MEM_secure_free(kB2_prime, kem->length_shared_secret);
  OQS_MEM_secure_free(sid, sid_length);*/
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(remote_peer_pubk);
  EVP_PKEY_free(privk);
}
