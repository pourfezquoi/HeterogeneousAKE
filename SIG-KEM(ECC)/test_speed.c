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




int main(void)
{

  
    
  uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
  uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
  uint8_t sendA[SEED_BYTES + SEED_BYTES + 2*SEED_BYTES];
  size_t sendAlen = 0;
  uint8_t st[3*SEED_BYTES];
  uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
  uint8_t sendB[SEED_BYTES];
  size_t sendBlen = 0;
  ake_keygen_lkey_A(lpka, lska);
  ake_keygen_lkey_B(lpkb, lskb);
//printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", algname_kem_nist[0], kem_cca->claimed_nist_level, algname_sig_nist[0], sig->claimed_nist_level, sig->euf_cma);
     

  PRINT_TIMER_HEADER
  TIME_OPERATION_ITERATIONS(
    ake_send_A(lska, lpka, lpkb, sendA, &sendAlen, st),
    "init",
    NTESTS
  )
     
  TIME_OPERATION_ITERATIONS(
		ake_send_B(lpka, sendA, sendAlen, lpkb, lskb, kb, sendB, &sendBlen),
    "algB",
    NTESTS
  )


  TIME_OPERATION_ITERATIONS(
		ake_receive_A(lpka, lska, lpkb, st, sendB, ka),
    "algA",
    NTESTS
  )
  PRINT_TIMER_FOOTER


  return 0;
}
