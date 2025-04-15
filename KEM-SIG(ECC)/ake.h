#include <stdint.h>
#include "api.h" 
#include <openssl/evp.h>


int ake_keygen_lkey_A(uint8_t *lpka, uint8_t *lska);
int ake_keygen_lkey_B(uint8_t *lpkb, uint8_t *lskb);
int ake_send_A(uint8_t *epka, uint8_t *eska);
int ake_send_B(const uint8_t *lpka, 
    const uint8_t *recv, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen);
int ake_receive_A(const uint8_t *lpka, const uint8_t *lska, 
    const uint8_t *epka, const uint8_t *eska, const uint8_t *recv, const size_t recvlen, const uint8_t *lpkb, uint8_t *k);