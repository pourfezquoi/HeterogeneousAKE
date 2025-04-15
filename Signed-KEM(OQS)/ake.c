#include "ake.h"
#include "fips202.h"
#include <string.h>



int ake_keygen_lkey_A(OQS_SIG* sig, uint8_t *lpka, uint8_t *lska) {
    if (sig->keypair(lpka, lska) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_keygen_lkey_B(OQS_SIG* sig, uint8_t *lpkb, uint8_t *lskb) {
    if (sig->keypair(lpkb, lskb) != OQS_SUCCESS) {
        printf("Error creating long term key for B. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_send_A(OQS_SIG* sig, OQS_KEM* kem_cpa, uint8_t *send, size_t *sendlen, uint8_t *epka, uint8_t *eska, const uint8_t *lpka, const uint8_t *lska, const uint8_t *lpkb) {
    
    if (kem_cpa->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }

    uint8_t sigma[sig->length_signature];
    size_t siglen=0;

    if (sig->sign(sigma, &siglen, epka, kem_cpa->length_public_key, lska)) {
        printf("Error signing by B. Exiting.\n");
		exit(-1);
    }

    memcpy(send, epka, kem_cpa->length_public_key);
    memcpy(send + kem_cpa->length_public_key, sigma, siglen);
    *sendlen = kem_cpa->length_public_key + siglen;
    return 0;
}

int ake_send_B(OQS_SIG* sig, OQS_KEM* kem_cpa, const uint8_t *lpka, 
                const uint8_t *recv, const size_t recvlen, const uint8_t *lpkb, 
                const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cpa->length_ciphertext], ss1[kem_cpa->length_shared_secret];
    
    uint8_t sigma[sig->length_signature];
    uint8_t epka[kem_cpa->length_public_key];

    size_t mlen = kem_cpa->length_public_key;
    size_t mlen2 = mlen + kem_cpa->length_ciphertext;
    uint8_t buf[mlen2];

    memcpy(epka, recv, kem_cpa->length_public_key);
    memcpy(sigma, recv + kem_cpa->length_public_key, recvlen - kem_cpa->length_public_key);
    
    if (sig->verify(epka, mlen, sigma, recvlen - kem_cpa->length_public_key, lpka) != OQS_SUCCESS) {
        printf("Verification fails.\n");
		exit(-1);
    }

    if (kem_cpa->cpa_encaps(ct1, ss1, epka)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }

    memcpy(buf, epka, mlen);
    memcpy(buf + mlen, ct1, kem_cpa->length_ciphertext);

    size_t siglen=0;
    if (sig->sign(sigma, &siglen, buf, mlen2, lskb)) {
        printf("Error signing by B. Exiting.\n");
		exit(-1);
    }

    uint8_t hash_k_input[mlen2+kem_cpa->length_shared_secret];
    
    memcpy(hash_k_input, buf, mlen2);    
    memcpy(hash_k_input + mlen2, ss1, kem_cpa->length_shared_secret);
   
    shake256(k, SESSION_KEY_LEN, hash_k_input, mlen2+kem_cpa->length_shared_secret);
    
    *sendlen = kem_cpa->length_ciphertext + siglen;
    //send = (uint8_t *) calloc (*sendlen, sizeof(uint8_t));

    memcpy(send, ct1, kem_cpa->length_ciphertext);
    memcpy(send + kem_cpa->length_ciphertext, sigma, siglen);

    return 0;

}

int ake_receive_A(OQS_SIG* sig, OQS_KEM* kem_cpa, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *epka, uint8_t *eska, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, uint8_t *k) {

    
    uint8_t sigma[sig->length_signature], ct1[kem_cpa->length_ciphertext], ss1[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cpa->length_ciphertext, len=0;
    uint8_t buf[mlen];
    memcpy(ct1, recv, kem_cpa->length_ciphertext);
    memcpy(sigma, recv + kem_cpa->length_ciphertext, recvlen - kem_cpa->length_ciphertext);

    memcpy(buf, epka, kem_cpa->length_public_key);
    len = kem_cpa->length_public_key;
    memcpy(buf + len, ct1, kem_cpa->length_ciphertext);
    //len = len + kem_cpa->length_ciphertext;
    
    if (sig->verify(buf, mlen, sigma, recvlen - kem_cpa->length_ciphertext, lpkb) != OQS_SUCCESS) {
        printf("Verification fails.\n");
		exit(-1);
    }

    kem_cpa->cpa_decaps(ss1, ct1, eska);

    uint8_t hash_k_input[mlen+kem_cpa->length_shared_secret];
    
    memcpy(hash_k_input, buf, mlen);    
    memcpy(hash_k_input + mlen, ss1, kem_cpa->length_shared_secret);
   
    shake256(k, SESSION_KEY_LEN, hash_k_input, mlen + kem_cpa->length_shared_secret);
    
    return 0;
}



