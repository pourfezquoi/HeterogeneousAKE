#include "ake.h"
#include <string.h>




int main(){
    int errcount = 0;
    uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
            
    ake_keygen_lkey_A(lpka, lska);
            
    uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
    ake_keygen_lkey_B(lpkb, lskb);
            
    uint8_t epka[SEED_BYTES], eska[SEED_BYTES];
    ake_send_A(epka, eska);
            
    uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
    uint8_t send[SEED_BYTES+SEED_BYTES+2*SEED_BYTES];
    size_t sendlen = 0;
    ake_send_B(lpka, epka, lpkb, lskb, kb, send, &sendlen);
    ake_receive_A(lpka, lska, epka, eska, send, sendlen, lpkb, ka);
          
    if (memcmp(ka, kb, SESSION_KEY_LEN) != 0) {
        errcount++;
    }

    printf("sendA len: %d\n", SEED_BYTES);
    printf("sendB len: %zu\n", sendlen);
    printf("session key len: %d\n", SESSION_KEY_LEN);
    

    printf("AKE err numbers: %d\n", errcount);
    
    
}