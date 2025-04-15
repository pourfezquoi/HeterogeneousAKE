#include "ake.h"
#include <string.h>



int main(){
    int errcount = 0;
    
        
        /*kem_cca = OQS_KEM_new(algname_kem_nist[i]);
        kem_cpa = OQS_KEM_new(algname_kem_nist[i]);

        printf("KEM: %s, cca:%d\n", kem_cca->method_name, kem_cca->ind_cca);*/

        
            uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];
            ake_keygen_lkey_A(lpka, lska);
            
            uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
            ake_keygen_lkey_B(lpkb, lskb);
            
            uint8_t sendA[SEED_BYTES + SEED_BYTES + 2*SEED_BYTES];
            size_t sendAlen = 0;
            uint8_t st[3*SEED_BYTES];
            ake_send_A(lska, lpka, lpkb, sendA, &sendAlen, st);

            uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
            uint8_t sendB[SEED_BYTES];
            size_t sendBlen = 0;
            ake_send_B(lpka, sendA, sendAlen, lpkb, lskb, kb, sendB, &sendBlen);
            
            ake_receive_A(lpka, lska, lpkb, st, sendB, ka);
            
            if (memcmp(ka, kb, SESSION_KEY_LEN) != 0) {
                printf("--- error! ---\n");
                printf("ka=%x, kb=%x\n", ka[0], kb[0]);
                errcount++;
            }

            printf("sendA len: %zu\n", sendAlen);
            printf("sendB len: %zu\n", sendBlen);
            printf("session key len: %d\n", SESSION_KEY_LEN);
        
    

    printf("AKE err numbers: %d\n", errcount);
    
    
}