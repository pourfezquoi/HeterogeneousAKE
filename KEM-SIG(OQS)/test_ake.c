#include "ake.h"


#define ALGNUMS_KEM 18
#define ALGNUMS_KEM_NIST 3
//#define ALGNUMS_KEM_NIST 1
#define ALGNUMS_SIG 44
#define ALGNUMS_SIG_NIST 19
//#define ALGNUMS_SIG_NIST 2

char algname_kem_nist[ALGNUMS_KEM_NIST][OQS_KEM_algs_length] = {
    OQS_KEM_alg_ml_kem_512,
    OQS_KEM_alg_ml_kem_768,
    OQS_KEM_alg_ml_kem_1024
};

char algname_kem[ALGNUMS_KEM][OQS_KEM_algs_length] = {
    /*OQS_KEM_alg_bike_l1,
    OQS_KEM_alg_bike_l3,
    OQS_KEM_alg_bike_l5,
    OQS_KEM_alg_classic_mceliece_348864,*/
    OQS_KEM_alg_classic_mceliece_348864,
    OQS_KEM_alg_classic_mceliece_348864f,
    OQS_KEM_alg_classic_mceliece_460896,
    OQS_KEM_alg_classic_mceliece_460896f,
    OQS_KEM_alg_classic_mceliece_6688128,
    OQS_KEM_alg_classic_mceliece_6688128f,
    OQS_KEM_alg_classic_mceliece_6960119,
    OQS_KEM_alg_classic_mceliece_8192128,
    OQS_KEM_alg_classic_mceliece_8192128f,
    OQS_KEM_alg_hqc_128,
    OQS_KEM_alg_hqc_192,
    OQS_KEM_alg_hqc_256,
    OQS_KEM_alg_frodokem_640_aes,
    OQS_KEM_alg_frodokem_640_shake,
    OQS_KEM_alg_frodokem_976_aes,
    OQS_KEM_alg_frodokem_976_shake,
    OQS_KEM_alg_frodokem_1344_aes,
    OQS_KEM_alg_frodokem_1344_shake
    //OQS_KEM_alg_kyber_512,
    //OQS_KEM_alg_ml_kem_512
    /*OQS_KEM_alg_ntruprime_sntrup761,
    OQS_KEM_alg_frodokem_640_aes*/
    
};

char algname_sig_nist[ALGNUMS_SIG_NIST][OQS_SIG_algs_length] = {
    OQS_SIG_alg_ml_dsa_44,
    OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,

    OQS_SIG_alg_falcon_512,
    OQS_SIG_alg_falcon_1024,
    OQS_SIG_alg_falcon_padded_512,
    OQS_SIG_alg_falcon_padded_1024,

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
    OQS_SIG_alg_sphincs_shake_256s_simple
};

char algname_sig[ALGNUMS_SIG][OQS_SIG_algs_length] = {
    OQS_SIG_alg_dilithium_2,
    OQS_SIG_alg_dilithium_3,
    OQS_SIG_alg_dilithium_5,

    OQS_SIG_alg_ml_dsa_44,
    OQS_SIG_alg_ml_dsa_65,
    OQS_SIG_alg_ml_dsa_87,

    OQS_SIG_alg_falcon_512,
    OQS_SIG_alg_falcon_1024,
    OQS_SIG_alg_falcon_padded_512,
    OQS_SIG_alg_falcon_padded_1024,

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
    OQS_SIG_alg_sphincs_shake_256s_simple,

    OQS_SIG_alg_mayo_1,
    OQS_SIG_alg_mayo_2,
    OQS_SIG_alg_mayo_3,
    OQS_SIG_alg_mayo_5,

    OQS_SIG_alg_cross_rsdp_128_balanced,
    OQS_SIG_alg_cross_rsdp_128_fast,
    OQS_SIG_alg_cross_rsdp_128_small,
    OQS_SIG_alg_cross_rsdp_192_balanced,
    OQS_SIG_alg_cross_rsdp_192_fast,
    OQS_SIG_alg_cross_rsdp_192_small,
    OQS_SIG_alg_cross_rsdp_256_balanced,
    OQS_SIG_alg_cross_rsdp_256_fast,
    OQS_SIG_alg_cross_rsdp_256_small,
    OQS_SIG_alg_cross_rsdpg_128_balanced,
    OQS_SIG_alg_cross_rsdpg_128_fast,
    OQS_SIG_alg_cross_rsdpg_128_small,
    OQS_SIG_alg_cross_rsdpg_192_balanced,
    OQS_SIG_alg_cross_rsdpg_192_fast,
    OQS_SIG_alg_cross_rsdpg_192_small,
    OQS_SIG_alg_cross_rsdpg_256_balanced,
    OQS_SIG_alg_cross_rsdpg_256_fast,
    OQS_SIG_alg_cross_rsdpg_256_small
};


int main(){
    int errcount = 0;
    
    OQS_KEM *kem_cca, *kem_cpa;
    OQS_SIG *sig;
    //OQS_SIG_STFL *sig_stfl;
    //for (int i=0; i<ALGNUMS_KEM; i++) { 
    for (int i=0; i<ALGNUMS_KEM_NIST; i++) { 
        
        kem_cca = OQS_KEM_new(algname_kem_nist[i]);
        kem_cpa = OQS_KEM_new(algname_kem_nist[i]);

        printf("KEM: %s, cca:%d\n", kem_cca->method_name, kem_cca->ind_cca);

        //for (int j=0; j<ALGNUMS_SIG; j++) {
        for (int j=0; j<ALGNUMS_SIG_NIST; j++) {
            
            sig = OQS_SIG_new(algname_sig_nist[j]);
            if( (kem_cca->claimed_nist_level != sig->claimed_nist_level) && (kem_cca->claimed_nist_level+1 != sig->claimed_nist_level)) {
                //printf("continue, kem level=%d, sig level=%d\n\n",kem_cca->claimed_nist_level, sig->claimed_nist_level);
                continue;
            }

            printf("\n================ KEM: %s NIST_LEVEL: %d SIG: %s NIST_LEVEL: %d EUF-CMA: %d================\n", kem_cca->method_name, kem_cca->claimed_nist_level, sig->method_name, sig->claimed_nist_level, sig->euf_cma);
            
            uint8_t lpka[kem_cca->length_public_key], lska[kem_cca->length_secret_key];
            
            ake_keygen_lkey_A(kem_cca, lpka, lska);
            
            uint8_t lpkb[sig->length_public_key], lskb[sig->length_secret_key];
            ake_keygen_lkey_B(sig, lpkb, lskb);
            
            uint8_t epka[kem_cpa->length_public_key], eska[kem_cpa->length_secret_key];
            ake_send_A(kem_cpa, epka, eska);
            
            uint8_t ka[SESSION_KEY_LEN], kb[SESSION_KEY_LEN];// *send = NULL;
            uint8_t send[kem_cca->length_ciphertext+kem_cpa->length_ciphertext+sig->length_signature];
            size_t sendlen = 0;
            ake_send_B(kem_cca, kem_cpa, sig, lpka, epka, lpkb, lskb, kb, send, &sendlen);
            ake_receive_A(kem_cca, kem_cpa, sig, lpka, lska, epka, eska, send, sendlen, lpkb, ka);
          
            if (OQS_MEM_secure_bcmp(ka, kb, SESSION_KEY_LEN) != 0) {
                errcount++;
            }

            printf("sendA len: %zu\n", kem_cpa->length_public_key);
            printf("sendB len: %zu\n", sendlen);
            printf("session key len: %d\n", SESSION_KEY_LEN);
        }
    }

    printf("AKE err numbers: %d\n", errcount);
    
    
}