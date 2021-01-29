# AES128 CCM code compatible with PSOC 4 
Modified AES-128 CCM code for working with Cypress PSOC 4 encoding functions. Based on OpenSSL

# Some Notes:
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
 
