#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "ake.h"
#include "cpucycles.h"
#include "speed_print.h"
#include "ds_benchmark.h"

#define NTESTS 100000

uint64_t t[NTESTS];

#define ALGNUMS_KEM_NIST 1

char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    /*OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024*/
};



int main(void)
{
  

  
  for (int j=0;j<ALGNUMS_KEM_NIST;j++) {
    OQS_KEM *kem_cca, *kem_cpa;
    kem_cca = OQS_KEM_new(algname_kem_nist[j]);
    kem_cpa = OQS_KEM_new(algname_kem_nist[j]);
    //OQS_SIG *sig;
    //sig = OQS_SIG_new(algname_sig_nist[0]);
    uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
      uint8_t lpkb[kem_cca->length_public_key], lskb[kem_cca->length_secret_key];
      uint8_t sendA[kem_cpa->length_public_key + kem_cca->length_ciphertext + 2*SEED_BYTES];
      size_t sendAlen = 0;
      uint8_t st[SEED_BYTES + kem_cca->length_shared_secret + kem_cca->length_ciphertext];
      uint8_t epka[kem_cpa->length_public_key];
      uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
      uint8_t sendB[kem_cpa->length_ciphertext];
      size_t sendBlen = 0;
    ake_keygen_lkey_A(lpka, lska);
    ake_keygen_lkey_B(kem_cca, lpkb, lskb);
    //printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", algname_kem_nist[0], kem_cca->claimed_nist_level, algname_sig_nist[0], sig->claimed_nist_level, sig->euf_cma);
     

    PRINT_TIMER_HEADER 
    TIME_OPERATION_ITERATIONS(
      ake_send_A(kem_cpa, kem_cca, lpka, lska, lpkb, epka, sendA, &sendAlen, st),
      "init",
      NTESTS
    )
      
    TIME_OPERATION_ITERATIONS(
      ake_send_B(kem_cca, kem_cpa, lpka, sendA, sendAlen, lpkb, lskb, kb, sendB, &sendBlen),
      "algB",
      NTESTS
    )


    TIME_OPERATION_ITERATIONS(
      ake_receive_A(kem_cca, kem_cpa, lpka, lska, lpkb, st, sendB, ka),
      "algA",
      NTESTS
    )
    PRINT_TIMER_FOOTER
  }

  return 0;
}
