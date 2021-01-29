

#include "aes_ccm.h"

/* Some Notes:
 * PSOC4 uses AES-CCM 128 bits which is popular in BLE standard.
 * IV (=Initial Vector) is named "nonce" is PSOC terminology and is 13 bytes.
 * Tag is named MIC and is 4 bytes.
 * AAD is not used in PSOC decoding functions and according to its docs a 1 bytes should be
 * used
 * Plaintext is the raw data. Its size is limited to 27 bytes in PSOC functions.
 * 
 * Here we use OpenSSL library. To install it on linux use:
 * sudo apt install libss-dev
 * Find the location of installed library:
 * dpkg-query -L libssl-dev
 * Add this parameters to GCC for compiling. You can use MakeFile as well:
 * gcc XXX.c XXXXX.c -L{OPENSSL_LOCATION} -lcrypto -lssl
 * On Ubuntu 18 and 20 {OPENSSL_LOCATION} = /usr/lib/x86_64-linux-gnu/
 */

void handleErrors(void) {
    printf("Error Occured! \n");
}


int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *nonce,
                unsigned char *ciphertext,
                unsigned char *mic)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Setting IV len to 13. Default in PSOC 4
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 13, NULL))
        handleErrors();

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 4, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
        handleErrors();

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 4, mic))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *nonce,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

    /* Setting IV len to 13. Default in PSOC 4*/
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 13, NULL))
        handleErrors();

    /* Set expected tag value. */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 4, tag))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))
        handleErrors();


    /* Provide the total ciphertext length */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

