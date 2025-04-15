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
#define ALGNUMS_SIG_NIST 1

char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    /*OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024*/
};

char algname_sig_nist[ALGNUMS_SIG_NIST][OQS_SIG_algs_length] = {
    OQS_SIG_alg_ml_dsa_44,
    /*OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,

    OQS_SIG_alg_falcon_512,*/
    /*//OQS_SIG_alg_falcon_1024,
    OQS_SIG_alg_falcon_padded_512,
    //OQS_SIG_alg_falcon_padded_1024,

    OQS_SIG_alg_sphincs_sha2_128f_simple,
    OQS_SIG_alg_sphincs_sha2_128s_simple,
    OQS_SIG_alg_sphincs_sha2_192f_simple,
    OQS_SIG_alg_sphincs_sha2_192s_simple,
    OQS_SIG_alg_sphincs_sha2_256f_simple,
    OQS_SIG_alg_sphincs_sha2_256s_simple,
    OQS_SIG_alg_sphincs_shake_128f_simple,
    OQS_SIG_alg_sphincs_shake_128s_simple,
    OQS_SIG_alg_sphincs_shake_192f_simple,
    OQS_SIG_alg_sphincs_shake_192s_simple,
    OQS_SIG_alg_sphincs_shake_256f_simple,
    OQS_SIG_alg_sphincs_shake_256s_simple*/
};


int main(void)
{
  OQS_KEM *kem_cpa;
  OQS_SIG *sig;

  for (int i=0; i<ALGNUMS_KEM_NIST; i++) {   
    kem_cpa = OQS_KEM_new(algname_kem_nist[i]);  
    for (int j=0; j<ALGNUMS_SIG_NIST; j++) {
      sig = OQS_SIG_new(algname_sig_nist[j]);
      printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", algname_kem_nist[j], kem_cpa->claimed_nist_level, algname_sig_nist[0], sig->claimed_nist_level, sig->euf_cma);
      uint8_t lpka[sig->length_public_key], lska[sig->length_secret_key];
      uint8_t lpkb[sig->length_public_key], lskb[sig->length_secret_key];
      uint8_t eska[kem_cpa->length_secret_key], epka[kem_cpa->length_public_key];
      uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];//*send = NULL;
      uint8_t sendA[kem_cpa->length_public_key + sig->length_signature], sendB[kem_cpa->length_ciphertext+sig->length_signature];
      size_t sendALen = 0, sendlen = 0;
      ake_keygen_lkey_A(sig, lpka, lska);
      ake_keygen_lkey_B(sig, lpkb, lskb);   
      PRINT_TIMER_HEADER  
      TIME_OPERATION_ITERATIONS(
        ake_send_A(sig, kem_cpa, sendA, &sendALen, epka, eska, lpka, lska, lpkb),
        "init",
        NTESTS
      )
        
      TIME_OPERATION_ITERATIONS(
        ake_send_B(sig, kem_cpa, lpka, sendA, sendALen, lpkb, lskb, kb, sendB, &sendlen),
        "algB",
        NTESTS
      )


      TIME_OPERATION_ITERATIONS(
        ake_receive_A(sig, kem_cpa, lpka, lska, epka, eska, sendB, sendlen, lpkb, ka),
        "algA",
        NTESTS
      )
      PRINT_TIMER_FOOTER
    }
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
