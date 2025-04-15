#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "ake.h"
#include "cpucycles.h"
#include "speed_print.h"
#include "ds_benchmark.h"

#define NTESTS 100000
//#define NTESTS 1

uint64_t t[NTESTS];

#define ALGNUMS_KEM_NIST 1
char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    /*OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024*/
};


int main(void)
{
  OQS_KEM *kem_cpa;
  for (int i=0; i<ALGNUMS_KEM_NIST; i++) {   
    kem_cpa = OQS_KEM_new(algname_kem_nist[i]);  

    uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
    uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
    uint8_t eska[kem_cpa->length_secret_key], epka[kem_cpa->length_public_key];
    uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];//*send = NULL;
    uint8_t sendA[kem_cpa->length_public_key + 2*SEED_BYTES], sendB[kem_cpa->length_ciphertext+2*SEED_BYTES];
    size_t sendlen = 0;
    ake_keygen_lkey_A(lpka, lska);
    ake_keygen_lkey_B(lpkb, lskb);   
    PRINT_TIMER_HEADER  
    //printf("%10s | %14s | %15s | %10s | %25s \n", "", "", "", "", "");
    TIME_OPERATION_ITERATIONS(
      ake_send_A(kem_cpa, sendA, epka, eska, lpka, lska, lpkb),
      "init",
      NTESTS
    )
      
    TIME_OPERATION_ITERATIONS(
      ake_send_B(kem_cpa, lpka, sendA, lpkb, lskb, kb, sendB, &sendlen),
      "algB",
      NTESTS
    )


    TIME_OPERATION_ITERATIONS(
      ake_receive_A(kem_cpa, lpka, lska, epka, eska, sendB, sendlen, lpkb, ka),
      "algA",
      NTESTS
    )
    PRINT_TIMER_FOOTER
  }
  /*
    for (int k=0; k<ALGNUMS_SIG_NIST; k++) {
      OQS_SIG *sig;
      sig = OQS_SIG_new(algname_sig_nist[k]);
      if( (kem_cca->claimed_nist_level != sig->claimed_nist_level) && (kem_cca->claimed_nist_level+1 != sig->claimed_nist_level)) {
        continue;
      }
      

      

      printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", algname_kem_nist[j], kem_cca->claimed_nist_level, algname_sig_nist[k], sig->claimed_nist_level, sig->euf_cma);
            
      for(i=0;i<NTESTS;i++) {
        t[i] = cpucycles();
        ake_keygen_lkey_A(kem_cca, lpka, lska);
      }
      print_results("ake_init gen long term keys for A: ", t, NTESTS);

      for(i=0;i<NTESTS;i++) {
        t[i] = cpucycles();
        ake_keygen_lkey_B(sig, lpkb, lskb);
      }
      print_results("ake_init gen long term keys for B: ", t, NTESTS);

      for(i=0;i<NTESTS;i++) {
        t[i] = cpucycles();
        ake_send_A(kem_cpa, epka, eska);
      }
      print_results("ake_send_a: ", t, NTESTS);

      for(i=0;i<NTESTS;i++) {
        t[i] = cpucycles();
        ake_send_B(kem_cca, kem_cpa, sig, lpka, epka, lpkb, lskb, kb, send, &sendlen);
      }
      print_results("ake_send_b: ", t, NTESTS);

      for(i=0;i<NTESTS;i++) {
        t[i] = cpucycles();
        ake_receive_A(kem_cca, kem_cpa, sig, lpka, lska, epka, eska, send, sendlen, lpkb, ka);
      }
      print_results("ake_receive_a: ", t, NTESTS);
    }
    
  }*/

  return 0;
}
