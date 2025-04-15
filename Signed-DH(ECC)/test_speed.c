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




int main(void)
{
  uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
  uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
  uint8_t epka[SEED_BYTES];
  EVP_PKEY *eska = NULL;
  uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];//*send = NULL;
  uint8_t sendA[3*SEED_BYTES], sendB[3*SEED_BYTES];
  size_t sendlen = 0;
  ake_keygen_lkey_A(lpka, lska);
  ake_keygen_lkey_B(lpkb, lskb);   
     
  PRINT_TIMER_HEADER
  TIME_OPERATION_ITERATIONS(
    ake_send_A(sendA, epka, eska, lska),
    "init",
    NTESTS
  )
     
  TIME_OPERATION_ITERATIONS(
		ake_send_B(lpka, sendA, lpkb, lskb, kb, sendB, &sendlen),
    "algB",
    NTESTS
  )


  TIME_OPERATION_ITERATIONS(
		ake_receive_A(lpka, lska, epka, eska, sendB, sendlen, lpkb, ka),
    "algA",
    NTESTS
  )
  PRINT_TIMER_FOOTER

  return 0;
}
