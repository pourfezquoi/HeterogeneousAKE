#include "ake.h"
#include "fips202.h"
#include <oqs/sha3_ops.h>
#include <string.h>


int ake_keygen_lkey_A(OQS_KEM* kem, uint8_t *lpka, uint8_t *lska) {
    if (kem->keypair(lpka, lska) != OQS_SUCCESS) {
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

int ake_send_A(OQS_KEM* kem, uint8_t *epka, uint8_t *eska) {
    //if (kem->keypair(epka, eska) != OQS_SUCCESS) {
    if (kem->cpa_keypair(epka, eska) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_send_B(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, OQS_SIG* sig, const uint8_t *lpka, const uint8_t *recv, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cca->length_ciphertext], ss1[kem_cca->length_shared_secret];
    uint8_t ct2[kem_cpa->length_ciphertext], ss2[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext + kem_cpa->length_ciphertext;
    uint8_t buf[mlen];
    size_t tmplen = 0;
    uint8_t sigma[sig->length_signature];
    size_t siglen=0;
    
    if (kem_cca->encaps(ct1, ss1, lpka) != OQS_SUCCESS) {
        printf("Error encapsulating by kem_cca. Exiting.\n");
		exit(-1);
    }
    //if (kem_cpa->encaps(ct2, ss2, recv)) {
    if (kem_cpa->cpa_encaps(ct2, ss2, recv)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }
    
    memcpy(buf, recv, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(buf + tmplen, ct1, kem_cca->length_ciphertext);
    tmplen = tmplen + kem_cca->length_ciphertext;
    memcpy(buf + tmplen, ct2, kem_cpa->length_ciphertext);
    if (sig->sign(sigma, &siglen, buf, mlen, lskb)) {
        printf("Error signing by B. Exiting.\n");
		exit(-1);
    }


    size_t len = 0, len2=0;
    len2 = kem_cca->length_public_key + sig->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;
    
    memcpy(hash_k_input + len, lpkb, sig->length_public_key);
    len = len + sig->length_public_key;
    
    memcpy(hash_k_input + len, recv, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;
    
    memcpy(hash_k_input + len, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;
    
    memcpy(hash_k_input + len, ss2, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss1, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    /*printf("sendb len=%d, hash_k_input=\n",len);
    for(int i=0;i<len;i++){
        printf("%x, ", hash_k_input[i]);
    }
    printf("\n\n");*/
    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    *sendlen = kem_cca->length_ciphertext + kem_cpa->length_ciphertext + siglen;
    //send = (uint8_t *) calloc (*sendlen, sizeof(uint8_t));

    len = 0;
    memcpy(send, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(send + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(send + len, sigma, siglen);
    len = len + siglen;

    return 0;

}

int ake_receive_A(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, OQS_SIG* sig, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *epka, const uint8_t *eska, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, uint8_t *k) {


    uint8_t ct_cca[kem_cca->length_ciphertext], ss_cca[kem_cca->length_shared_secret];
    uint8_t ct_cpa[kem_cpa->length_ciphertext], ss_cpa[kem_cpa->length_shared_secret];
    size_t len = 0;

    uint8_t sigma[sig->length_signature];

    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext + kem_cpa->length_ciphertext;
    uint8_t buf[mlen];
    size_t tmplen = 0;
    
    memcpy(ct_cca, recv, kem_cca->length_ciphertext);
    len = kem_cca->length_ciphertext;
    memcpy(ct_cpa, recv + len, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(sigma, recv + len, recvlen - len);

    memcpy(buf, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(buf + tmplen, ct_cca, kem_cca->length_ciphertext);
    tmplen = tmplen + kem_cca->length_ciphertext;
    memcpy(buf + tmplen, ct_cpa, kem_cpa->length_ciphertext);
    if (sig->verify(buf, mlen, sigma, recvlen - len, lpkb) != OQS_SUCCESS) {
        printf("Verification fails.\n");
		exit(-1);
    }

    //kem_cpa->decaps(ss_cpa, ct_cpa, eska);
    kem_cpa->cpa_decaps(ss_cpa, ct_cpa, eska);

    kem_cca->decaps(ss_cca, ct_cca, lska);

    len = 0;
    size_t len2=0;
    len2 = kem_cca->length_public_key + sig->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    
    memcpy(hash_k_input, lpka, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;
    
    memcpy(hash_k_input + len, lpkb, sig->length_public_key);
    len = len + sig->length_public_key;
    
    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct_cpa, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;
    
    memcpy(hash_k_input + len, ct_cca, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;
    
    memcpy(hash_k_input + len, ss_cpa, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss_cca, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;
    
    //OQS_SHA3_shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    shake256(k, SESSION_KEY_LEN, hash_k_input, len);


    return 0;
}



