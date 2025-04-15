#include <stdint.h>
#include <oqs/oqs.h>
#include "api.h" 

int ake_keygen_lkey_A(uint8_t *lpka, uint8_t *lska);
int ake_keygen_lkey_B(OQS_KEM* kem, uint8_t *lpkb, uint8_t *lskb);
int ake_send_A(OQS_KEM* kem_cpa, OQS_KEM* kem_cca, const uint8_t *lpka, const uint8_t *lska, const uint8_t *lpkb, uint8_t *epka, uint8_t *send, size_t *sendlen, uint8_t *st);
int ake_send_B(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *recv, const size_t recvlen, const uint8_t *lpkb, const uint8_t *lskb, 
    uint8_t *k, uint8_t *send, size_t *sendlen);
int ake_receive_A(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *lpkb, const uint8_t *st, const uint8_t *recv, 
    uint8_t *k); 