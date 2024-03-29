#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>

class encryption
{
    public:
        void handle_errors(void);
        void encryption_error(void);
        void decryption_error(void);
        int get_SHA256(void* input, unsigned long length, unsigned char* md);
        int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
        int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

    private:

};
