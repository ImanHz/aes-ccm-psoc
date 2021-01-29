#include "aes_ccm.h"

int main(int argc, char **argv)
{

uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
uint8_t nonce[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
uint8_t aad[1] = {1};
uint8_t input[4] = {0x0B, 0x16, 0x21, 0x2C};

// Calculated in encryption proccess:
uint8_t mic[4] = {0};
uint8_t out[4] = {0}; // Is called CypherText. It is the encoded data.

printf("===  ENCRYPT === \n");

ccm_encrypt(input, 4,
                aad, 1,
                key,
                nonce,
                out,
                mic);

for (uint8_t i = 0; i < 4; i++) {
    printf("%X \t %X \n", out[i], mic[i]);
}

char decoded[4];

ccm_decrypt(out, 4, aad, 1, mic, key, nonce, decoded);

printf("===  DECRYPT === \n");

for (uint8_t i = 0; i < 4; i++) {
    printf("%X \n", decoded[i]);
}

}
