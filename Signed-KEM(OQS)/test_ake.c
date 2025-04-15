#include "ake.h"
#include <string.h>

#define ALGNUMS_KEM_NIST 1
#define ALGNUMS_SIG_NIST 7

char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    /*OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024*/
};

char algname_sig_nist[ALGNUMS_SIG_NIST][OQS_SIG_algs_length] = {
    OQS_SIG_alg_ml_dsa_44,
    /*OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,*/

    OQS_SIG_alg_falcon_512,
    //OQS_SIG_alg_falcon_1024,
    OQS_SIG_alg_falcon_padded_512,
    //OQS_SIG_alg_falcon_padded_1024,

    OQS_SIG_alg_sphincs_sha2_128f_simple,
    OQS_SIG_alg_sphincs_sha2_128s_simple,
    /*OQS_SIG_alg_sphincs_sha2_192f_simple,
    OQS_SIG_alg_sphincs_sha2_192s_simple,
    OQS_SIG_alg_sphincs_sha2_256f_simple,
    OQS_SIG_alg_sphincs_sha2_256s_simple,*/
    OQS_SIG_alg_sphincs_shake_128f_simple,
    OQS_SIG_alg_sphincs_shake_128s_simple,
    /*OQS_SIG_alg_sphincs_shake_192f_simple,
    OQS_SIG_alg_sphincs_shake_192s_simple,
    OQS_SIG_alg_sphincs_shake_256f_simple,
    OQS_SIG_alg_sphincs_shake_256s_simple*/
};

int main(){
    int errcount = 0;
    OQS_KEM *kem_cpa;
    OQS_SIG *sig;

    for (int i=0; i<ALGNUMS_KEM_NIST; i++) {   
        kem_cpa = OQS_KEM_new(algname_kem_nist[i]);  
        for (int j=0; j<ALGNUMS_SIG_NIST; j++) {
            sig = OQS_SIG_new(algname_sig_nist[j]);

            uint8_t lpka[sig->length_public_key], lska[sig->length_secret_key];      
            ake_keygen_lkey_A(sig, lpka, lska);
            
            printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", kem_cpa->method_name, kem_cpa->claimed_nist_level, sig->method_name, sig->claimed_nist_level, sig->euf_cma);
                   
            uint8_t lpkb[sig->length_public_key], lskb[sig->length_secret_key];
            ake_keygen_lkey_B(sig, lpkb, lskb);
                    
            uint8_t sendA[kem_cpa->length_public_key + sig->length_signature];
            size_t sendALen = 0;
            uint8_t eska[kem_cpa->length_secret_key], epka[kem_cpa->length_public_key];
            ake_send_A(sig, kem_cpa, sendA, &sendALen, epka, eska, lpka, lska, lpkb);
                    
            uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
            uint8_t send[kem_cpa->length_ciphertext + sig->length_signature];
            size_t sendlen = 0;
            ake_send_B(sig, kem_cpa, lpka, sendA, sendALen, lpkb, lskb, kb, send, &sendlen);
            ake_receive_A(sig, kem_cpa, lpka, lska, epka, eska, send, sendlen, lpkb, ka);
                
            if (memcmp(ka, kb, SESSION_KEY_LEN) != 0) {
                errcount++;
            }

            printf("sendA len: %ld\n", sendALen);
            printf("sendB len: %zu\n", sendlen);
            printf("session key len: %d\n", SESSION_KEY_LEN);
        }
    }
    

    printf("AKE err numbers: %d\n", errcount);
    
    
}