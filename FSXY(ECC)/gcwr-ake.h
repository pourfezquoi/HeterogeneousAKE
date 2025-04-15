#ifndef GCWR_AKE_H
#define GCWR_AKE_H

#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rand.h>
#include "utils.h"

#define MAX 16
#define U_A "Party A"
#define U_B "Party B"

int is_mceliece(OQS_KEM* kem);

void concat_keys(const uint8_t *key1, const uint8_t *key2, const uint8_t *key3,
                 size_t length, uint8_t *out);

void gen_sk(uint8_t *sid, uint8_t *concat_keys, size_t length_sid, size_t length_concat_keys, uint8_t *sk);
void hash_key(const unsigned char *message, size_t message_len, unsigned char *digest);

void concat_sid(
                const char UA[PID_LENGTH],
                const char UB[PID_LENGTH],
                const uint8_t *ekA1,
                const uint8_t *ekB1,
                const uint8_t *cA1,
                const uint8_t *ekA2,
                const uint8_t *cB1,
                const uint8_t *cB2,
                uint8_t *sid);

void ake_init(
              uint8_t* ekB1,
              uint8_t* cA1,
              uint8_t* kA1,
              uint8_t* ekA2,
              uint8_t* dkA2);

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
              uint8_t* skB);

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
              uint8_t* skB);
#endif
