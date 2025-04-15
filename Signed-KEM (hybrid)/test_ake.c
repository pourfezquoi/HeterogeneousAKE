#include "ake.h"
#include <string.h>

#define ALGNUMS_KEM_NIST 1
char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    /*OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024*/
};


int main(){
    int errcount = 0;
    OQS_KEM *kem_cpa;
    
    for (int i=0; i<ALGNUMS_KEM_NIST; i++) {   
        kem_cpa = OQS_KEM_new(algname_kem_nist[i]);  

        uint8_t lpka[SEED_BYTES], lska[SEED_BYTES];      
        ake_keygen_lkey_A(lpka, lska);
        
        printf("\n================ KEM: %s NIST_LEVEL: %d SIG: Ed25519 ================\n", kem_cpa->method_name, kem_cpa->claimed_nist_level);
                  
        uint8_t lpkb[SEED_BYTES], lskb[SEED_BYTES];
        ake_keygen_lkey_B(lpkb, lskb);
                
        uint8_t sendA[kem_cpa->length_public_key + 2*SEED_BYTES];
        uint8_t eska[kem_cpa->length_secret_key], epka[kem_cpa->length_public_key];
        ake_send_A(kem_cpa, sendA, epka, eska, lpka, lska, lpkb);
                
        uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
        uint8_t send[kem_cpa->length_ciphertext+2*SEED_BYTES];
        size_t sendlen = 0;
        ake_send_B(kem_cpa, lpka, sendA, lpkb, lskb, kb, send, &sendlen);
        ake_receive_A(kem_cpa, lpka, lska, epka, eska, send, sendlen, lpkb, ka);
            
        if (memcmp(ka, kb, SESSION_KEY_LEN) != 0) {
            errcount++;
        }

        printf("sendA len: %ld\n", kem_cpa->length_public_key + 2*SEED_BYTES);
        printf("sendB len: %zu\n", sendlen);
        printf("session key len: %d\n", SESSION_KEY_LEN);
    }
    

    printf("AKE err numbers: %d\n", errcount);
    
    
}