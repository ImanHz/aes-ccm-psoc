/*
 * Copyright 2013-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// Modified Program for Cypress PSOC 4 AES-128 Decoding. 


#include <stdio.h>
#include "string.h"
#include <openssl/bio.h>
#include <openssl/evp.h>


void handleErrors(void);

int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *nonce,
                unsigned char *ciphertext,
                unsigned char *mic);



int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *nonce,
                unsigned char *plaintext);