#include "ake.h"
#include "fips202.h"
#include <oqs/sha3_ops.h>
#include <string.h>

int ake_keygen_lkey_A(OQS_SIG* sig, uint8_t *lpka, uint8_t *lska) {
    
    if (sig->keypair(lpka, lska) != OQS_SUCCESS) {
        printf("Error creating long term key for B. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_keygen_lkey_B(OQS_KEM* kem, uint8_t *lpkb, uint8_t *lskb) {
    if (kem->keypair(lpkb, lskb) != OQS_SUCCESS) {
        printf("Error creating long term key for A. Exiting.\n");
		exit(-1);
    }
    return 0;
}

int ake_send_A(OQS_KEM* kem_cpa, OQS_KEM* kem_cca, OQS_SIG* sig, const uint8_t *lpka, const uint8_t *lska, 
                const uint8_t *lpkb, uint8_t *epka, uint8_t *send, size_t *sendlen, uint8_t *st) {
    uint8_t buf[SEED_BYTES + sig->length_secret_key], r[SEED_BYTES];
    uint8_t ct[kem_cca->length_ciphertext], ss[kem_cca->length_shared_secret];
    uint8_t eska[kem_cpa->length_secret_key];

    OQS_randombytes(buf, SEED_BYTES);
    memcpy(buf + SEED_BYTES, lska, sig->length_secret_key);
    sha3_256(r, buf, SEED_BYTES + sig->length_secret_key);
    
    if (kem_cpa->cpa_keypair_derand(epka, eska, r) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }

    if (kem_cca->encaps(ct, ss, lpkb) != OQS_SUCCESS) {
        printf("Error encapsulating by kem_cca. Exiting.\n");
		exit(-1);
    }
    
    uint8_t sigma[sig->length_signature];
    size_t siglen=0;
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t sigmessage[mlen];
    size_t tmplen = 0;
    memcpy(sigmessage, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(sigmessage + tmplen, ct, kem_cca->length_ciphertext);
    
    if (sig->sign(sigma, &siglen, sigmessage, mlen, lska)) {
        printf("Error signing by B. Exiting.\n");
		exit(-1);
    }
    /*memcpy(send, epka, kem_cpa->length_public_key);
    memcpy(send + kem_cpa->length_public_key, ct, kem_cca->length_ciphertext);*/
    memcpy(send, sigmessage, mlen);
    memcpy(send + mlen, sigma, siglen);
    *sendlen = mlen + siglen;

    //store r0|ss|ct into state
    memcpy(st, buf, SEED_BYTES);
    memcpy(st + SEED_BYTES, ss, kem_cca->length_shared_secret); 
    memcpy(st + SEED_BYTES + kem_cca->length_shared_secret, ct, kem_cca->length_ciphertext); 

    return 0;
}

int ake_send_B(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, OQS_SIG* sig, const uint8_t *lpka, const uint8_t *recv, 
    const size_t recvlen, const uint8_t *lpkb, const uint8_t *lskb, uint8_t *k, uint8_t *send, size_t *sendlen) {
    
    uint8_t ct1[kem_cca->length_ciphertext], ss1[kem_cca->length_shared_secret];
    uint8_t ct2[kem_cpa->length_ciphertext], ss2[kem_cpa->length_shared_secret];
    
    size_t mlen = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t epka[kem_cpa->length_public_key];
    size_t tmplen2 = kem_cpa->length_public_key + kem_cca->length_ciphertext;
    uint8_t sigma[recvlen - tmplen2];

    memcpy(epka, recv, kem_cpa->length_public_key);
    memcpy(ct1, recv + kem_cpa->length_public_key, kem_cca->length_ciphertext);
    memcpy(sigma, recv + tmplen2, recvlen - tmplen2);

    /*uint8_t sigmessage[mlen];
    memcpy(sigmessage, recv, mlen);
    size_t tmplen = 0;
    memcpy(sigmessage, epka, kem_cpa->length_public_key);
    tmplen = kem_cpa->length_public_key;
    memcpy(sigmessage + tmplen, ct1, kem_cca->length_ciphertext);*/
    
    if (sig->verify(recv, mlen, sigma, recvlen - tmplen2, lpka) != OQS_SUCCESS) {
        printf("Verification fails.\n");
		exit(-1);
    }

    //if (kem_cpa->encaps(ct2, ss2, recv)) {
    if (kem_cpa->cpa_encaps(ct2, ss2, epka)) {
        printf("Error encapsulating by kem_cpa. Exiting.\n");
		exit(-1);
    }
    
    kem_cca->decaps(ss1, ct1, lskb);
    

    size_t len = 0, len2=0;
    len2 = sig->length_public_key + kem_cca->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    memcpy(hash_k_input, lpka, sig->length_public_key);
    len = len + sig->length_public_key;

    memcpy(hash_k_input + len, lpkb, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;

    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, ct2, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(hash_k_input + len, ct1, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(hash_k_input + len, ss2, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss1, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    memcpy(send, ct2, kem_cpa->length_ciphertext);
    *sendlen = kem_cpa->length_ciphertext;

    return 0;

}

int ake_receive_A(OQS_KEM* kem_cca, OQS_KEM* kem_cpa, OQS_SIG* sig, const uint8_t *lpka, 
    const uint8_t *lska, const uint8_t *lpkb, const uint8_t *st, const uint8_t *recv, 
    uint8_t *k) {
    
    uint8_t epka[kem_cpa->length_public_key], eska[kem_cpa->length_secret_key], ss_cpa[kem_cpa->length_shared_secret];
    uint8_t ct_cca[kem_cca->length_ciphertext], ss_cca[kem_cca->length_shared_secret];
    uint8_t buf[SEED_BYTES + sig->length_secret_key], r[SEED_BYTES];

    memcpy(buf, st, SEED_BYTES);
    memcpy(ss_cca, st + SEED_BYTES, kem_cca->length_shared_secret);
    memcpy(ct_cca, st + SEED_BYTES + kem_cca->length_shared_secret, kem_cca->length_ciphertext);
    memcpy(buf + SEED_BYTES, lska, sig->length_secret_key);
    sha3_256(r, buf, SEED_BYTES + sig->length_secret_key);
    if (kem_cpa->cpa_keypair_derand(epka, eska, r) != OQS_SUCCESS) {
        printf("Error creating ephemeral key for A. Exiting.\n");
		exit(-1);
    }
    kem_cpa->cpa_decaps(ss_cpa, recv, eska);

    size_t len = 0, len2=0;
    len2 = sig->length_public_key + kem_cca->length_public_key + kem_cpa->length_public_key + 
            kem_cpa->length_ciphertext + kem_cca->length_ciphertext + kem_cpa->length_shared_secret + kem_cca->length_shared_secret;
    uint8_t hash_k_input[len2];
    memcpy(hash_k_input, lpka, sig->length_public_key);
    len = len + sig->length_public_key;

    memcpy(hash_k_input + len, lpkb, kem_cca->length_public_key);
    len = len + kem_cca->length_public_key;

    memcpy(hash_k_input + len, epka, kem_cpa->length_public_key);
    len = len + kem_cpa->length_public_key;

    memcpy(hash_k_input + len, recv, kem_cpa->length_ciphertext);
    len = len + kem_cpa->length_ciphertext;

    memcpy(hash_k_input + len, ct_cca, kem_cca->length_ciphertext);
    len = len + kem_cca->length_ciphertext;

    memcpy(hash_k_input + len, ss_cpa, kem_cpa->length_shared_secret);
    len = len + kem_cpa->length_shared_secret;
    
    memcpy(hash_k_input + len, ss_cca, kem_cca->length_shared_secret);
    len = len + kem_cca->length_shared_secret;

    shake256(k, SESSION_KEY_LEN, hash_k_input, len);
    
    return 0;
}



